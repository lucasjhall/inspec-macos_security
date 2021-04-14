'''
Quick attempt to systematically generate Inspec test from the macOS Security Project.
https://github.com/usnistgov/macos_security
'''
from __future__ import print_function
from jinja2 import Template
import generate_baseline as b

# Double quote where needed, then escape
def escape_chars(string):
    '''
    Escape double quotes initially, add more to maketrans as needed.
    '''
    return string.translate(str.maketrans({"\"":  r"\"",}))


# Inspec Test Template via jinja
INSPEC_TEMPLATE = Template(
    'control \'{{control}}\' do\n  title \'{{title}}\'\n  desc \
    \"{{desc}}\"\n  impact {{impact}}\n  describe command(\"{{test}}\") \
    do\n    {{exit}}\n  end\nend')


def sev_to_inspec(in_sev):
    '''
    Convert macOS Security Severity to Inspec Weight
    '''
    if in_sev == 'missing':
        return 0
    elif in_sev == 'high':
        return 1.0
    elif in_sev == 'medium':
        return 0.5
    elif in_sev == 'low':
        return 0.1

    return 0

# Prettify the block
def indent_desc(string):
    '''
    Indent and clean up the spacing of the desc field.
    '''
    new = "\n"
    space = "    "
    new += space + escape_chars(string.replace("\n", "\n    "))
    return new

def exit_to_ruby(test_dict):
    '''
    Translate security exit to ruby logic
    '''
    if 'integer' in test_dict:
        return "its('exit_status') { should eq %s }" % test_dict['integer']
    elif 'boolean' in test_dict:
        return "its('exit_status') { should eq %s }" % test_dict['boolean']
    elif 'string' in test_dict:
        return "its('stdout') { should match(/%s/) }"  % test_dict['string']

    return None

def load_rules():
    '''
    Logic taken directly from generate_baseline.py
    '''

    all_rules = b.collect_rules()

    return all_rules

def aggregate_controls(rules):
    '''
    Determine Controls from prefixes in the namespace of the rules
    '''
    controls = set([])
    for rule in rules:
        controls.add(rule.rule_id.partition('_')[0])
    return controls

def create_tests(controls, rules):
    '''
    Create the tests from the gathered controls and their rules.
    '''
    for control in controls:
        print("Processing control: {}".format(control))
        for rule in rules:
            inspec_tests = ""
            if "{}_".format(control) in rule.rule_id:
                print("  Processing rule: {}".format(rule.rule_id))
                print("    Tags: {}".format(rule.rule_tags))
                if any(item in ['inherent',
                                'permanent',
                                'n_a',
                                'supplemental']
                       for item in rule.rule_tags):
                    # Account for controls without tests/results
                    print("    Skipped test, skip tag.")
                elif not exit_to_ruby(rule.rule_result_value):
                    # Account for controls without tests/results
                    print("    Skipped test, no result.")
                else:
                    print("    Generated test.")
                    sev = sev_to_inspec(rule.rule_severity)
                    inspec_tests += INSPEC_TEMPLATE.render(
                        control=rule.rule_id,
                        title=rule.rule_title.replace("\'", "\\\'"),
                        desc=indent_desc(rule.rule_discussion).replace("\n    \n", "\n"),
                        impact=sev,
                        test=escape_chars(rule.rule_check.replace("\\", "").rstrip()),
                        exit=exit_to_ruby(rule.rule_result_value)
                    )
                    inspec_tests += "\n"
            try:
                test = open("../inpsec-macos_security/controls/{}.rb".format(control), "a")
                test.write(inspec_tests)
                test.close()
            except Exception as err:
                print("Error writing file:")
                print(err)
                print("See the README for folder structure and execution.")
                print("This script assumes its being ran from within\
                     the macos_security/scripts directory.")

def main():
    '''
    Load rules from macOS Security project,
    aggregate controls and then create tests.
    '''
    rules = load_rules()
    controls = aggregate_controls(rules)
    create_tests(controls, rules)

if __name__ == "__main__":
    main()
