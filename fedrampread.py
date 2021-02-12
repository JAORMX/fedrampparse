#!/usr/bin/env python3
"""
This small utility parses all the FedRAMP controls and displays the
compliance as code content rules that apply to those controls.
"""
import argparse
import os
import logging
import re
import sys
import tempfile

import git
import pandas as pd
import requests
import sh
import yaml


FEDRAMP_SHEET = 'https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx'
COMPLIANCE_CONTENT_REPO = 'https://github.com/ComplianceAsCode/content.git'
OPENCONTROL_REPO = 'https://github.com/ComplianceAsCode/redhat.git'

logging.basicConfig(level=logging.INFO)
subsectionsre = re.compile(".*([a-z])")

def ensure_cachedir():
    directory = ".fedrampcachedir"
    try:
        os.stat(directory)
    except FileNotFoundError:
        os.mkdir(directory)       
    return directory



def get_fedramp_sheet(workspace):
    """ Get the FedRAMP controls excel sheet """
    logging.info("Fetching FedRAMP controls sheet from: %s", FEDRAMP_SHEET)
    fedramp_path = os.path.join(workspace, 'fedrampcontrols.xlsx')
    try:
        os.stat(fedramp_path)
    except FileNotFoundError:
        with open(fedramp_path, 'wb') as fedramp_file:
            fedramp_content = requests.get(FEDRAMP_SHEET).content
            fedramp_file.write(fedramp_content)
    return fedramp_path


def get_compliance_content(workspace):
    """ Clone the ComplianceAsCode content repository """
    logging.info("Fetching ComplianceAsCode content repository: %s",
                 COMPLIANCE_CONTENT_REPO)
    content_path = os.path.join(workspace, 'compliance-content')
    try:
        os.stat(content_path)
    except FileNotFoundError:
        os.mkdir(content_path)
        git.Repo.clone_from(COMPLIANCE_CONTENT_REPO, content_path, branch='master')
    return content_path


def get_opencontrol_content(workspace):
    """ Clone the opencontrol content repository """
    logging.info("Fetching opencontrol repository: %s", OPENCONTROL_REPO)
    oc_path = os.path.join(workspace, 'opencontrol')
    try:
        os.stat(oc_path)
    except FileNotFoundError:
        os.mkdir(oc_path)
        git.Repo.clone_from(OPENCONTROL_REPO, oc_path, branch='master')
    return oc_path


def normalize_control(control):
    control = control.replace(" ", "")
    if control.endswith(")"):
        if subsectionsre.match(control):
            return control[:-3]
    return control


def get_fedramp_controls(fedramp_path, baseline):
    """ Get a list of controls that apply to FedRAMP according to the given
    baseline."""
    xlfile = pd.ExcelFile(fedramp_path)
    df1 = xlfile.parse('%s Baseline Controls' % baseline.capitalize())
    # The first line doesn't contain the right titles... e.g. "Unnamed: 3"
    # after getting the title, the next line contains the actual titles... so
    # we skip it. The rest should be the actual list of controls.
    controls = set(map(normalize_control, df1['Unnamed: 3'][1:]))
    logging.info("We'll check against %s FedRAMP controls", len(controls))
    return controls


def iterate_components(proddir):
    components = sh.find(proddir, "-name", "component.yaml").rstrip().split("\n")
    for comppath in components:
        with open(comppath) as comp:
            yield yaml.safe_load(comp)


def filter_fedramp_controls(product, controls, opencontrol_path):
    # Maps the CaC names to opencontrol names
    product_mapping = {
        "rhcos4": "coreos-4",
        "ocp4": "openshift-container-platform-4",
        "rhel7": "rhel-7",
        "rhel8": "rhel-8",
    }
    if not product_mapping.get(product, False):
        return controls

    logging.info("Filtering FedRAMP controls based on the opencontrol assessment")

    assessed_controls = set()
    unapplicable_controls = set()
    proddir = os.path.join(opencontrol_path, product_mapping[product], "policies")
    for component in iterate_components(proddir):
        for control in component:
            assessed_controls.add(normalize_control(control["control_key"]))

            if control["implementation_status"] == "not applicable":
                unapplicable_controls.add(normalize_control(control["control_key"]))

    unassessed_controls = controls.difference(assessed_controls)
    if len(unassessed_controls) > 1:
        logging.info("There are %s controls that appear in the baseline but were not assessed:\n\t%s",
                    len(assessed_controls), ", ".join(unassessed_controls))
    else:
        logging.info("All FedRAMP controls were assessed in OpenControl")

    # Return applicable controls coming from the baseline itself
    return controls.difference(unapplicable_controls)


def print_files_for_controls(fedramp_controls, content_path, output_file):
    """ Print the relevant files from the ComplianceAsCode project that are
    relevant to the NIST controls """
    for control in fedramp_controls:
        command = (("grep -R 'nist:' %s | grep '%s' |grep rule.yml | " +
                    "awk '{print $1}' | sed 's/:$//' | sed 's@^%s@@'") %
                   (content_path, control, content_path + '/'))
        stdout = os.popen(command)
        output = stdout.read()
        if output:
            output_file.write("The control '%s' is mentioned in the following "
                              "rules:\n\n" % control)
            output_file.write(output)
            output_file.write("\n")


def get_profile_root(pinfo, content_path):
    """ Gets a canonical path for the profile root out of the product information
    and the downloaded content"""
    pname = pinfo["product"]
    proot = pinfo["profiles_root"]
    return os.path.join(content_path, pname, proot)


def find_moderate_profiles(proot):
    raw_profiles = sh.find(proot, "-name", "*moderate*")
    return raw_profiles.rstrip().split("\n")


def try_getting_parsed_selection(sel, name):
    try:
        selinfo = yaml.safe_load(sel)
        selinfo["name"] = name
        return selinfo
    except yaml.YAMLError as err:
        pmark = getattr(err, "problem_mark")
        deletecmd = "{}d".format(pmark.line)
        # reset file
        if hasattr(sel, "seek"):
            sel.seek(0)
        fixedsel = sh.sed(deletecmd, _in=sel).stdout
        return try_getting_parsed_selection(fixedsel, name)

def fetch_selection(selections_path, selection):
        seldirpath = sh.find(selections_path, "-name", selection).rstrip()
        selpath = os.path.join(seldirpath, "rule.yml")
        with open(selpath) as sfile:
            return try_getting_parsed_selection(sfile, selection)

def iterate_selections(ppaths, pinfo, content_path):
    broot = pinfo["benchmark_root"]
    selections_path = os.path.join(content_path, pinfo["product"], broot)
    # Iterate profiles
    for ppath in ppaths:
        with open(ppath) as pfile:
            profile = yaml.load(pfile, Loader=yaml.BaseLoader)
            # iterate and parse selections
            for selection in profile["selections"]:
                # We skip variable settings
                if "=" in selection:
                    continue
                yield fetch_selection(selections_path, selection)


def get_product_info(product, content_path):
    """ Parses the product description """
    product_info_file = os.path.join(content_path, product, "product.yml")
    with open(product_info_file) as fil:
        info = yaml.load(fil, Loader=yaml.BaseLoader)
        return info


def get_applicable_references(selection, pname):
    refs = selection.get("references", dict())
    output = set()
    for refkey, refval in refs.items():
        if refkey in ["nist@" + pname, "nist"]  :
            normalized_refs = map(normalize_control, refval.split(","))
            output.update(normalized_refs)
    return output


def print_stats(product_info, fedramp_controls, content_path, output_file):
    """ Print the relevant statistics on how the controls are covered for a certain
    product """
    proot = get_profile_root(product_info, content_path)
    profilespaths = find_moderate_profiles(proot)

    addressed_controls = set()

    logging.info("Parsing selections...")
    for selection in iterate_selections(profilespaths, product_info, content_path):
        refs = get_applicable_references(selection, product_info["product"])
        addressed_controls.update(refs)


    print("\nStatistics summary:\n")

    total = len(fedramp_controls)
    addressed = addressed_controls.intersection(fedramp_controls)
    print("Addressed controls: %s/%s\n\t%s\n" % (len(addressed), total, ', '.join(addressed)))

    diff = addressed_controls.difference(fedramp_controls)
    print("Controls addressed, not applicable to this baseline: %s/%s\n\t%s\n" % (len(diff), total, ', '.join(diff)))

    unaddressed = fedramp_controls.difference(addressed)
    print("Unaddressed controls: %s/%s\n\t%s\n" % (len(unaddressed), total, ', '.join(unaddressed)))


def main():
    """ read the fedramp controls! """
    parser = argparse.ArgumentParser(
        description='Print the FedRAMP controls and their respective '
                    'content files.')
    parser.add_argument('file',
                        nargs='?',
                        default=sys.stdout,
                        type=argparse.FileType('w'),
                        help='The file to output the result to.')
    parser.add_argument('--baseline',
                        default='moderate',
                        choices=['low', 'moderate', 'high'],
                        help='The baseline to output the results for.')
    parser.add_argument('--product',
                        default='rhcos4',
                        help="The product that's being evaluated.")
    args = parser.parse_args()

    workspace = ensure_cachedir()
    fedramp_path = get_fedramp_sheet(workspace)
    fedramp_controls = get_fedramp_controls(fedramp_path, args.baseline)
    content_path = get_compliance_content(workspace)
    oc_path = get_opencontrol_content(workspace)
    #print_files_for_controls(fedramp_controls, content_path, args.file)
    product_info = get_product_info(args.product, content_path)
    fedramp_controls = filter_fedramp_controls(args.product, fedramp_controls, oc_path)
    print_stats(product_info, fedramp_controls, content_path, args.file)

if __name__ == '__main__':
    logging.getLogger("sh").setLevel(logging.WARNING)
    main()
