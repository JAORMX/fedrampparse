"""
This small utility parses all the FedRAMP controls and displays the
compliance as code content rules that apply to those controls.
"""
import argparse
import os
import logging
import sys
import tempfile

import git
import pandas as pd
import requests


FEDRAMP_SHEET = 'https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx'
COMPLIANCE_CONTENT_REPO = 'https://github.com/ComplianceAsCode/content.git'


def get_fedramp_sheet(workspace):
    """ Get the FedRAMP controls excel sheet """
    logging.info("Fetching FedRAMP controls sheet from: %s", FEDRAMP_SHEET)
    fedramp_path = os.path.join(workspace, 'fedrampcontrols.xlsx')
    with open(fedramp_path, 'wb') as fedramp_file:
        fedramp_content = requests.get(FEDRAMP_SHEET).content
        fedramp_file.write(fedramp_content)
    return fedramp_path

def get_compliance_content(workspace):
    """ Clone the ComplianceAsCode content repository """
    logging.info("Fetching ComplianceAsCode content repository: %s",
                 COMPLIANCE_CONTENT_REPO)
    content_path = os.path.join(workspace, 'compliance-content')
    os.mkdir(content_path)
    git.Repo.clone_from(COMPLIANCE_CONTENT_REPO, content_path, branch='master')
    return content_path

def get_fedramp_controls(fedramp_path, baseline):
    """ Get a list of controls that apply to FedRAMP according to the given
    baseline."""
    xlfile = pd.ExcelFile(fedramp_path)
    df1 = xlfile.parse('%s Baseline Controls' % baseline.capitalize())
    # The first line doesn't contain the right titles... e.g. "Unnamed: 3"
    # after getting the title, the next line contains the actual titles... so
    # we skip it. The rest should be the actual list of controls.
    return df1['Unnamed: 3'][1:]

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
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as workspace:
        fedramp_path = get_fedramp_sheet(workspace)
        fedramp_controls = get_fedramp_controls(fedramp_path, args.baseline)
        content_path = get_compliance_content(workspace)
        print_files_for_controls(fedramp_controls, content_path, args.file)

if __name__ == '__main__':
    # logging.basicConfig(level=logging.INFO)
    main()
