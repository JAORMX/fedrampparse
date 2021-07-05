#!/usr/bin/env python3
"""
This small utility parses all the FedRAMP controls and displays the
compliance as code content rules that apply to those controls.
"""
import argparse
import collections
import os
import logging
import re
import subprocess
import sys

import git
import pandas as pd
import requests
import sh
import yaml
import json
from xml.etree import ElementTree

has_jira_bindings = True
try:
    import jira
except ImportError:
    has_jira_bindings = False


FEDRAMP_SHEET = 'https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx'
COMPLIANCE_CONTENT_REPO = 'https://github.com/ComplianceAsCode/content.git'
OPENCONTROL_REPO = 'https://github.com/ComplianceAsCode/redhat.git'

XCCDF12_NS = "http://checklists.nist.gov/xccdf/1.2"
OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
IGNITION_SYSTEM = "urn:xccdf:fix:script:ignition"
KUBERNETES_SYSTEM = "urn:xccdf:fix:script:kubernetes"
OCIL_SYSTEM = "http://scap.nist.gov/schema/ocil/2"
NIST_800_53_REFERENCE = "http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf"

XCCDF_RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
XCCDF_PROFILE_PREFIX = "xccdf_org.ssgproject.content_profile_"

JIRA_URL = "https://issues.redhat.com"

logging.basicConfig(level=logging.INFO)
subsectionsre = re.compile(".*([a-z])")
meetsre = re.compile(".*inherently me.*", re.IGNORECASE)
docsre = re.compile(".*addressed.*documentation.*", re.IGNORECASE)
jira_issue_re = re.compile('\[.*\]:')

def removeprefix(fullstr, prefix):
    if fullstr.startswith(prefix):
        return fullstr[len(prefix):]
    else:
        return fullstr

class XCCDFBenchmark:
    def __init__(self, filepath):
        self.tree = None
        with open(filepath, 'r') as xccdf_file:
            file_string = xccdf_file.read()
            tree = ElementTree.fromstring(file_string)
            self.tree = tree

        self.indexed_rules = {}
        for rule in self.tree.findall(".//{%s}Rule" % (XCCDF12_NS)):
            rule_id = rule.get("id")
            if rule_id is None:
                raise ValueError("Can't index a rule with no id attribute!")

            if rule_id in self.indexed_rules:
                raise ValueError("Multiple rules exist with same id attribute: %s!" % rule_id)

            self.indexed_rules[rule_id] = rule

    def get_rules(self, baseline):
        profile_name = XCCDF_PROFILE_PREFIX + baseline
        xccdf_profile = self.tree.find(".//{%s}Profile[@id=\"%s\"]" %
                                        (XCCDF12_NS, profile_name))
        if xccdf_profile is None:
            raise ValueError("No such profile: %s" % profile_name)

        rules = []
        selects = xccdf_profile.findall("./{%s}select[@selected=\"true\"]" %
                                        XCCDF12_NS)
        for select in selects:
            rule_id = select.get('idref')
            xccdf_rule = self.indexed_rules.get(rule_id)
            if xccdf_rule is None:
                # it could also be a Group
                continue
            rules.append(xccdf_rule)
        return rules

class RuleProperties:
    def __init__(self, profile_name, repo_path):
        self.profile_name = profile_name
        self.repo_path = repo_path

        self.rule_id = None
        self.name = None

        self.has_fix = False
        self.has_ocil = False
        self.has_oval = False
        self.has_e2etest = False

        self.nistrefs = list()

    def __str__(self):
        return "%s [OCIL %s, OVAL: %s, Fix: %s]" % (self.name, self.has_ocil, self.has_oval, self.has_fix)

    def from_element(self, el):
        self.rule_id = el.get("id")
        self.name = removeprefix(self.rule_id, XCCDF_RULE_PREFIX)

        oval = el.find("./{%s}check[@system=\"%s\"]" %
                         (XCCDF12_NS, OVAL_NS))
        ignition_fix = el.find("./{%s}fix[@system=\"%s\"]" %
                                 (XCCDF12_NS, IGNITION_SYSTEM))
        kubernetes_fix = el.find("./{%s}fix[@system=\"%s\"]" %
                                   (XCCDF12_NS, KUBERNETES_SYSTEM))
        ocil_check = el.find("./{%s}check[@system=\"%s\"]" %
                               (XCCDF12_NS, OCIL_SYSTEM))
        nistrefs_els = el.findall("./{%s}reference[@href=\"%s\"]" %
                           (XCCDF12_NS, NIST_800_53_REFERENCE))

        self.nistrefs = set([ normalize_control(ref.text) for ref in nistrefs_els ])

        self.has_ocil = False if ocil_check is None else True
        self.has_oval = False if oval is None else True

        has_ignition_fix = False if ignition_fix is None else True
        has_kubernetes_fix = False if kubernetes_fix is None else True
        self.has_fix = has_ignition_fix or has_kubernetes_fix
        return self

    def _get_rule_path(self):
        cmd = ["find", self.repo_path, "-name", self.name, "-type", "d"]
        process = subprocess.run(cmd, stdout=subprocess.PIPE, universal_newlines=True)
        if process.returncode != 0:
            print("WARNING: Rule path not found for rule: %s" % self.name)
            return None
        return process.stdout.strip("\n")

    def has_test(self):
        if self.repo_path is None:
            return
        path = self._get_rule_path()
        if path is None:
            return
        e2etestpath = os.path.join(path, "tests", "ocp4", "e2e.yml")
        if os.path.isfile(e2etestpath):
            self.has_e2etest = True

# subclass JSONEncoder
class setEncoder(json.JSONEncoder):
        def default(self, obj):
            return list(obj)


def jira_login(url, username, password_env):
    if has_jira_bindings == False:
        logging.warn("Please install python3-jira to enable fetching stats from Jira")
        return None
    password = os.getenv(password_env)

    options = dict()
    options['server'] = 'https://issues.redhat.com'
    conn = jira.JIRA(options, basic_auth=(username, password))
    os.unsetenv(password_env)
    if conn == None:
        logging.warn("Could not establish connection to Jira, check your password")
    else:
        logging.info("Established connection to Jira")
    return conn


def planned_controls_from_jira_epic(jira_conn, epic):
    if jira_conn == None or epic == "":
        logging.info("No connection or epic; skipping Jira statistics")
        return dict()

    jql = "key = {epic} OR \"Epic Link\" = {epic}".format(epic=epic)
    issues = jira_conn.search_issues(jql)

    controls_to_jira = collections.defaultdict(list)
    logging.info("Fetched %d issues from Jira linked to %s" % (len(issues), epic))
    for i in issues:
        # Don't report finished issues as in progress
        if i.fields.status.name == 'Done':
            continue

        update_control_to_jira_mapping(controls_to_jira, i)

    return controls_to_jira


def update_control_to_jira_mapping(controls_mapping, issue):
    controls = controls_from_jira(issue.fields.summary)
    for c in controls:
        controls_mapping[c.strip()].append(issue)


def controls_from_jira(summary):
    m = jira_issue_re.match(summary)
    if m is None:
        return []
    return summary[m.start()+1:m.end()-2].split(',')


def ensure_cachedir(dirbase):
    cachedir = ".fedrampcachedir"
    directory = os.path.join(dirbase, cachedir)
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

def get_ds_path(cac_repo, product, do_rebuild):
    ds_filename = "ssg-" + product + "-ds.xml"
    ds_path = os.path.join(cac_repo, "build", ds_filename)
    if do_rebuild:
        build_xccdf_content(cac_repo, product)
    else:
        if not os.path.exists(ds_path):
            raise IOError("DS %s not found and rebuild toggled off" % ds_path)
        logging.info("Reusing cached built content for %s in repo %s" % (product, cac_repo))
    
    return ds_path


def build_xccdf_content(cac_repo, product):
    logging.info("Rebuilding product %s in repo %s" % (product, cac_repo))
    buildscript_path = os.path.abspath(os.path.join(cac_repo, "build_product"))
    subprocess.run(check=True, capture_output=True, args=[
        buildscript_path, "--datastream-only", product], cwd=cac_repo)


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
    controls = set((normalize_control(x) for x in df1['Unnamed: 3'][1:] if isinstance(x, str)))
    logging.info("We'll check against %s FedRAMP controls", len(controls))
    return controls


def iterate_components(proddir):
    components = sh.find(proddir, "-name", "component.yaml").rstrip().split("\n")
    for comppath in components:
        with open(comppath) as comp:
            yield yaml.safe_load(comp)


def filter_fedramp_controls(product, controls, opencontrol_path):
    """ Filters applicable FedRAMP controls.

    It'll return a set of the controls that need addressed as well as a
    subset of the inherently met ones.
    """
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
    met_controls = set()
    docs_controls = set()
    proddir = os.path.join(opencontrol_path, product_mapping[product], "policies")
    for component in iterate_components(proddir):
        for control in component:
            nctrl = normalize_control(control["control_key"])
            assessed_controls.add(nctrl)

            if control["implementation_status"] == "not applicable":
                unapplicable_controls.add(nctrl)

            if control["implementation_status"] == "complete":
                for narrative in control["narrative"]:
                    if meetsre.search(narrative["text"]):
                        met_controls.add(nctrl)
                    if docsre.search(narrative["text"]):
                        docs_controls.add(nctrl)

    unassessed_controls = controls.difference(assessed_controls)
    if len(unassessed_controls) > 1:
        logging.info("There are %s controls that appear in the baseline but were not assessed:\n\t%s",
                    len(assessed_controls), ", ".join(unassessed_controls))
    else:
        logging.info("All FedRAMP controls were assessed in OpenControl")

    # Return applicable controls coming from the baseline itself
    return (controls.difference(unapplicable_controls), met_controls, docs_controls)


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
    product_info_file = os.path.join(content_path, "products", product, "product.yml")
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


def parse_rules_from_xccdf(baseline, repo_path, ds_path):
    rules = XCCDFBenchmark(ds_path).get_rules(baseline)
    xccdf_rules = []
    for rule in rules:
        rprop = RuleProperties(baseline, repo_path).from_element(rule)
        if rprop is None:
            continue
        rprop.has_test()
        xccdf_rules.append(rprop)
    return xccdf_rules


def stat_percentage(sub_i, total_i):
    sub = len(sub_i)
    total = len(total_i)
    if total == 0:
        percent = 0
    else:
        percent = 100.0 * (sub/total)
    return " %d/%d (%.2f%%)" % (sub, total, percent)


def print_stat_block(title, sub_i, total_i):
    print("\t" + title + " " + stat_percentage(sub_i, total_i))
    for i in sub_i:
        print("\t\t -", i)
    print("")


def print_stats(product_info, fedramp_controls, planned_controls, imet_controls, docs_controls, content_path, xccdf_rules):
    """ Print the relevant statistics on how the controls are covered for a certain
    product """
    proot = get_profile_root(product_info, content_path)

    xccdf_addressed_controls = set()

    rules_by_ref = dict()
    rules_missing_fix = list()
    rules_missing_oval = list()
    rules_missing_ocil = list()
    rules_missing_test = list()
    all_rule_names = list()
    for xrule in xccdf_rules:
        for ref in xrule.nistrefs:
            if ref in rules_by_ref.keys():
                rules_by_ref[ref].append(xrule)
            else:
                rules_by_ref[ref] = [xrule]

        xccdf_addressed_controls.update(xrule.nistrefs)
        all_rule_names.append(xrule.name)
        if xrule.has_fix == False:
            rules_missing_fix.append(xrule.name)
        if xrule.has_oval == False:
            rules_missing_oval.append(xrule.name)
        if xrule.has_ocil == False:
            rules_missing_ocil.append(xrule.name)
        if xrule.has_e2etest == False:
            rules_missing_test.append(xrule.name)

    print("\nStatistics summary:\n")

    total = len(fedramp_controls)
    met_controls = xccdf_addressed_controls | imet_controls
    met_controls = met_controls | docs_controls
    addressed = met_controls.intersection(fedramp_controls)
    print("Addressed controls: %s/%s\n\t%s\n" % (len(addressed), total, ', '.join(addressed)))

    xccdf_addressed = xccdf_addressed_controls.intersection(fedramp_controls)
    print("Addressed controls in XCCDF: %s/%s\n\t%s\n" % (len(xccdf_addressed), total, ', '.join(xccdf_addressed)))

    docs_met = docs_controls.intersection(fedramp_controls)
    print("Met via documentation: %s/%s\n\t%s\n" % (len(docs_met), total, ', '.join(docs_met)))

    inherently_met = imet_controls.intersection(fedramp_controls)
    print("Inherently met: %s/%s\n\t%s\n" % (len(inherently_met), total, ', '.join(inherently_met)))

    diff = met_controls.difference(fedramp_controls)
    print("Controls addressed, not applicable to this baseline: %s/%s\n\t%s\n" % (len(diff), total, ', '.join(diff)))

    print("Planned controls: %s/%s\n\t%s\n" % (len(planned_controls), total, ', '.join(planned_controls)))

    unaddressed = sorted(fedramp_controls.difference(addressed))
    print("Unaddressed controls: %s/%s\n\t%s\n" % (len(unaddressed), total, ', '.join(unaddressed)))

    unplanned = sorted(set(unaddressed).difference(planned_controls))
    print("Unplanned controls: %s/%s\n\t%s\n" % (len(unplanned), total, ', '.join(unplanned)))

    print("Rules per control:")
    for ctrl, rules in rules_by_ref.items():
        print("\t", ctrl)
        for rule in rules:
            print("\t\t - ", str(rule)) # TODO: Summary with rule properties as bits
        print("")

    print("Planned per control:")
    for ctrl, issues in planned_controls.items():
        print("\t", ctrl)
        for i in issues:
            print("\t\t - https://issues.redhat.com/browse/%s - %s" % (str(i.key), i.fields.summary))
        print("")

    print("Rule completeness stats")
    print_stat_block("Rules missing remediation", rules_missing_fix, xccdf_rules)
    print_stat_block("Rules missing oval", rules_missing_oval, xccdf_rules)
    print_stat_block("Rules missing ocil", rules_missing_ocil, xccdf_rules)
    print_stat_block("Rules missing tests", rules_missing_test, xccdf_rules)

def print_json(product_info, baseline, fedramp_controls, planned_controls, imet_controls, docs_controls, content_path, xccdf_rules, output_file):
    """ Print the relevant statistics on how the controls are covered for a certain
    product in JSON format"""
    proot = get_profile_root(product_info, content_path)

    xccdf_addressed_controls = set()

    rules_by_ref = dict()
    rules_missing_fix = list()
    rules_missing_oval = list()
    rules_missing_ocil = list()
    rules_missing_test = list()
    all_rule_names = list()
    for xrule in xccdf_rules:
        for ref in xrule.nistrefs:
            if ref in rules_by_ref.keys():
                rules_by_ref[ref].append(xrule)
            else:
                rules_by_ref[ref] = [xrule]

        xccdf_addressed_controls.update(xrule.nistrefs)
        all_rule_names.append(xrule.name)
        if xrule.has_fix == False:
            rules_missing_fix.append(xrule.name)
        if xrule.has_oval == False:
            rules_missing_oval.append(xrule.name)
        if xrule.has_ocil == False:
            rules_missing_ocil.append(xrule.name)
        if xrule.has_e2etest == False:
            rules_missing_test.append(xrule.name)

    data = dict()
    data["format_version"] = "v0.0.1"
    data["product_name"] = product_info["product"]
    data["benchmark"] = dict()
    data["benchmark"]["name"] = "FedRAMP"
    data["benchmark"]["baseline"] = baseline
    data["total_controls"] = len(fedramp_controls)

    met_controls = xccdf_addressed_controls | imet_controls | docs_controls
    data["addressed_controls"] = dict()
    data["addressed_controls"]["all"] = met_controls.intersection(fedramp_controls)
    data["addressed_controls"]["xccdf"] = xccdf_addressed_controls.intersection(fedramp_controls)
    data["addressed_controls"]["inherently"] = imet_controls.intersection(fedramp_controls)
    data["addressed_controls"]["docs"] = docs_controls.intersection(fedramp_controls)
    data["addressed_controls"]["not applicable"] = met_controls.difference(fedramp_controls)
    data["planned"] = planned_controls.keys()
    data["unaddressed"] = sorted(fedramp_controls.difference(data["addressed_controls"]["all"]))
    data["unplanned"] = sorted(set(data["unaddressed"]).difference(planned_controls))

    print(json.dumps(data, cls=setEncoder), file=output_file)

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
    parser.add_argument('--output',
                        default='orig',
                        choices=['orig', 'json'],
                        help="The output format.")
    parser.add_argument('--no-rebuild',
                        dest='rebuild',
                        action='store_false',
                        help='Do not rebuild the content in CaC checkout (default: rebuild)')
    parser.add_argument('--jira-username',
                        help="The usename to log to Jira with")
    parser.add_argument('--jira-epic',
                        help="The Jira epic for this work")
    parser.add_argument('--jira-password-env',
                        help="The environment variable that contains the Jira password")
    parser.add_argument('--cachedir',
                        default="./",
                        help='The directory to store the cache to.')
    args = parser.parse_args()

    jira_conn = None
    if args.jira_username and args.jira_password_env:
        jira_conn = jira_login(JIRA_URL, args.jira_username, args.jira_password_env)

    workspace = ensure_cachedir(args.cachedir)
    fedramp_path = get_fedramp_sheet(workspace)
    fedramp_controls = get_fedramp_controls(fedramp_path, args.baseline)
    content_path = get_compliance_content(workspace)

    oc_path = get_opencontrol_content(workspace)
    #print_files_for_controls(fedramp_controls, content_path, args.file)
    product_info = get_product_info(args.product, content_path)
    fedramp_controls, imet_controls, docs_controls = filter_fedramp_controls(args.product, fedramp_controls, oc_path)
    ds_path = get_ds_path(content_path, args.product, args.rebuild)
    xccdf_rules = parse_rules_from_xccdf(args.baseline, content_path, ds_path)
    planned_controls = planned_controls_from_jira_epic(jira_conn, args.jira_epic)
    if args.output == "orig":
        print_stats(product_info, fedramp_controls, planned_controls, imet_controls, docs_controls, content_path, xccdf_rules)
    else:
        print_json(product_info, args.baseline, fedramp_controls, planned_controls, imet_controls, docs_controls, content_path, xccdf_rules, args.file)

if __name__ == '__main__':
    logging.getLogger("sh").setLevel(logging.WARNING)
    main()
