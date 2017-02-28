#!/usr/bin/env python
"""Executable Python script for scanning source code for compliance.

   This script checks some (simple) conventions:
   - no symlinks
   - no tabs
   - no trailing whitespace
   - files end with EOL
   - valid license headers in source files (where applicable)
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""

import collections
import fnmatch
import itertools
import os
import platform
import re
import sys
import textwrap
import ConfigParser

VERBOSE = False

# Terminal colors
BLUE = '\033[94m'
CYAN = '\033[36m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[33m'

# Translatable messages (error and general)
ERR_INVALID_CONFIG_FILE = "Invalid configuration file [%s]: %s.\n"
ERR_LICENSE = "file does not include required license header."
ERR_SYMBOLIC_LINK = "file is a symbolic link."
ERR_TABS = "line contains tabs."
ERR_TRAILING_WHITESPACE = "line has trailing whitespaces."
ERR_NO_EOL_AT_EOF = "file does not end with EOL."
ERR_PATH_IS_NOT_DIRECTORY = "%s: %s is not a directory.\n"
WARN_CONFIG_SECTION_NOT_FOUND = "Configuration file section [%s] not found."
WARN_SCAN_EXCLUDING_PATHS = "  Excluding paths: %s"
WARN_SCAN_EXCLUDING_FILE = "  Excluding file: [%s]"
ERR_REQUIRED_SECTION = "Configuration file missing required section: [%s]"
ERR_GENERAL = "an unspecified error was detected."
MSG_CONFIG_ADDING_LICENSE_FILE = "Adding valid license from: [%s], value:\n%s"
MSG_SCANNING_STARTED = "Scanning files starting at [%s]..."
MSG_SCANNING_FILTER = "Scanning files with filter: [%s]:"
MSG_RUNNING_FILE_CHECKS = "    Running File Check [%s]"
MSG_RUNNING_LINE_CHECKS = "    Running Line Check [%s]"
MSG_CHECKING_FILE = "  [%s]..."
MSG_CHECKS_PASSED = "All checks passed."
MSG_SCRIPT_USAGE = "Usage: %s root_directory [-Verbose]\n"
MSG_ERROR_SUMMARY = "Scan detected %d error(s) in %d file(s):"

# Configuration file sections
DEFAULT_CONFIG_FILE = "scanCode.cfg"
SECTION_EXCLUDE = "Excludes"
SECTION_INCLUDE = "Includes"
SECTION_LICENSE = "Licenses"

# Globals
"""Hold valid license headers within an array strings."""
valid_licenses = []
exclusion_paths = []


def print_error(msg):
    """Print error message to stderr."""
    sys.stderr.write(col.red(msg) + "\n")


def print_warning(msg):
    """Print warning message to stdout."""
    print(col.yellow(msg))


def print_status(msg):
    """Print status message to stdout."""
    print(msg)


def print_success(msg):
    """Print success message to stdout."""
    print(col.green(msg))


def print_highlight(msg):
    """Print highlighted message to stdout."""
    print(col.cyan(msg))


def vprint(s):
    """Conditional print (stdout)."""
    if VERBOSE:
        print_status(s)


def get_config_section_dict(config, section):
    """Retrieve key-value pairs for requested section of a config. file."""
    dict1 = {}
    try:
        options = config.options(section)
        for option in options:
            try:
                dict1[option] = config.get(section, option)
            except:
                dict1[option] = None
    except:
        print_warning(WARN_CONFIG_SECTION_NOT_FOUND % section)
        return None
    return dict1


def read_license_files(config):
    """Read the license files to use when scanning source files."""
    file_dict = get_config_section_dict(config, SECTION_LICENSE)
    # vprint("license_file_dict: " + str(file_dict))
    if file_dict is not None:
        for key in file_dict:
            # Read and append entire text of each header to global array
            with open(file_dict[key], 'rb') as temp_file:
                str1 = str(temp_file.read())
                valid_licenses.append(str(str1))
                vprint(MSG_CONFIG_ADDING_LICENSE_FILE % (file_dict[key], str1))
    else:
        raise Exception(ERR_REQUIRED_SECTION % SECTION_LICENSE)


def read_path_exclusions(config):
    """Read the list of paths to exclude from the scan."""
    file_dict = get_config_section_dict(config, SECTION_EXCLUDE)
    # vprint("license_file_dict: " + str(file_dict))
    if file_dict is not None:
        for key in file_dict:
            print file_dict[key]
            exclusion_paths.append(str(file_dict[key]))
    else:
        raise Exception(ERR_REQUIRED_SECTION % SECTION_LICENSE)


def read_config_file():
    """Read in and validate configuration file."""
    try:
        filename = DEFAULT_CONFIG_FILE
        config = ConfigParser.ConfigParser()
        config.read([filename])
        read_license_files(config)
        read_path_exclusions(config)
    except Exception, e:
        print_error(e)
        return -1
    return 0


# def exceptional_paths():
#     """List of paths not subjected to the scan tests."""
#     return [
#         "bin/wskadmin",
#         "bin/wskdev",
#         "tests/build/reports",
#         "tests/exclude"
#     ]


def no_tabs(line):
    """Assert line does not contains a TAB character."""
    if re.match("\t", line):
        return ERR_TABS
    else:
        return None


def no_trailing_spaces(line):
    """Assert line does not have trailing whitespace."""
    if len(line) > 0 and line[-1] == '\n':
        line = line[:-1]

    if re.match("""^.*\s$""", line):
        return ERR_TRAILING_WHITESPACE
    else:
        return None


def eol_at_eof(line):
    """Assert line at End of File is an End of Line character."""
    if len(line) == 0 or line[-1] != '\n':
        return ERR_NO_EOL_AT_EOF
    else:
        return None


def has_block_license(path):
    """Open file and verify it contains a valid license header."""
    with open(path) as fp:
        for license in valid_licenses:
            # Assure license string is normalized to remove indentations
            # caused by declaration (above) as a string literal.
            normalized_license = textwrap.dedent(license)

            file_head = fp.read(len(normalized_license))

            if file_head is None:
                return [(1, ERR_LICENSE)]
            elif file_head == normalized_license:
                return []
            # reset and try finding the next license
            fp.seek(0)
    return [(1, ERR_LICENSE)]


def is_not_symlink(path):
    """Assert a file is not a symbolic link."""
    if os.path.islink(path):
        return [(0, ERR_SYMBOLIC_LINK)]
    else:
        return None


def line_checks(checks):
    """Turn file-based check into line-by-line checks on each file."""
    def run_line_checks(file_path):
        errors = []
        ln = 0
        # vprint(MSG_CHECKING_FILE % file_path)
        # For each line in the file, run all "line checks"
        with open(file_path) as fp:
            for line in fp:
                ln += 1
                for check in checks:
                    if ln == 1:
                        vprint(col.cyan(MSG_RUNNING_LINE_CHECKS %
                                        check.__name__))
                    err = check(line)
                    if err is not None:
                        errors.append((ln, err))
        return errors
    return run_line_checks


def run_file_checks(file_path, checks):
    """Run a series of file-by-file checks."""
    errors = []
    # if VERBOSE (True) then print filename being checked
    vprint(MSG_CHECKING_FILE % file_path)
    for check in checks:
        vprint(col.cyan(MSG_RUNNING_FILE_CHECKS % check.__name__))
        errs = check(file_path)
        if errs:
            errors += errs
    return errors


def all_paths(root_dir):
    """Generator that returns files with known extensions that can be scanned.

    Iteration is recursive beginning at the passed root directory and
    skipping directories that are listed as exception paths.
    """
    # print exceptional_paths()
    for dir_path, dir_names, files in os.walk(root_dir):
        for f in files:
            # if all(map(lambda p: not path.endswith(p), exceptional_paths())):
            # print "dir_path [%s]" % dir_path
            # print "f [%s]" % f
            # Map will contain a boolean for each exclusion path tested
            # as input to the lambda function
            # only if all() values in the Map are true should it yeild
            # a filename to run checks on
            # print list(map(lambda p: not dir_path.endswith(p),
            #                exceptional_paths()))
            if all(map(lambda p: not dir_path.endswith(p),
                       exclusion_paths)):
                yield os.path.join(dir_path, f)
            else:
                print_warning(WARN_SCAN_EXCLUDING_FILE %
                              os.path.join(dir_path, f))


def colors():
    """Create a collection of helper functions to colorize strings."""
    ansi = hasattr(sys.stderr, "isatty") and platform.system() != "Windows"

    def colorize(code, string):
        return "%s%s%s" % (code, string, '\033[0m') if ansi else string

    def cyan(s):
        return colorize(CYAN, s)

    def green(s):
        return colorize(GREEN, s)

    def red(s):
        return colorize(RED, s)

    def yellow(s):
        return colorize(YELLOW, s)

    return collections.namedtuple(
        "Colorizer",
        "cyan green red yellow")(cyan, green, red, yellow)

# Script entrypoint.
if __name__ == "__main__":

    # Prepare message colorization methods
    col = colors()

    # Test necessary arguments exist
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print_error(MSG_SCRIPT_USAGE % sys.argv[0])
        sys.exit(1)

    # Establish root director where scanning will start recursively
    root_dir = sys.argv[1]

    # Verbose flag, show detailed scanning information
    if len(sys.argv) == 3 and sys.argv[2] == "-Verbose":
        VERBOSE = True

    # Read / load configuration file
    if read_config_file() == -1:
        exit(1)

    # Verify starting path parameter is valid
    if not os.path.isdir(root_dir):
        print_error(ERR_PATH_IS_NOT_DIRECTORY %
                    (sys.argv[0], root_dir))
        exit(1)

    # This determines which checks run on which files.
    file_checks = [
        ("*", [is_not_symlink]),
        ("*.scala", [has_block_license,
                     line_checks([no_tabs,
                                  no_trailing_spaces,
                                  eol_at_eof])]),
        ("*.py", [line_checks([no_tabs,
                               no_trailing_spaces,
                               eol_at_eof])]),
        ("*.java", [has_block_license,
                    line_checks([
                        no_tabs,
                        no_trailing_spaces,
                        eol_at_eof])]),
        ("*.js", [line_checks([no_tabs,
                               no_trailing_spaces,
                               eol_at_eof])]),
        ("build.xml", [line_checks([no_tabs,
                                    no_trailing_spaces,
                                    eol_at_eof])]),
        ("deploy.xml", [line_checks([no_tabs, no_trailing_spaces,
                        eol_at_eof])]),
        ("*.gradle", [line_checks([no_tabs, no_trailing_spaces, eol_at_eof])]),
        ("*.md", [line_checks([no_tabs,
                               eol_at_eof])]),
        ("*.go", [has_block_license,
                  line_checks([no_tabs,
                               no_trailing_spaces,
                               eol_at_eof])])
    ]

    # Positive feedback to caller that scanning has started
    print_highlight(MSG_SCANNING_STARTED % root_dir)
    print_warning(WARN_SCAN_EXCLUDING_PATHS % str(exclusion_paths))

    # Runs all listed checks on all relevant files.
    all_errors = []
    for fltr, checks in file_checks:
        vprint(col.cyan(MSG_SCANNING_FILTER % fltr))
        for path in fnmatch.filter(all_paths(root_dir), fltr):
            errors = run_file_checks(path, checks)
            all_errors += map(lambda p: (path, p[0], p[1]), errors)

    def sort_key(p):
        """Define sort key for error listing as the filename."""
        # Filename is the 0th entry in tuple
        return p[0]

    if all_errors:
        # Group / sort errors by filename
        error_listing = ""
        files_with_errors = 0
        for path, triples in itertools.groupby(sorted(all_errors,
                                                      key=sort_key),
                                               key=sort_key):
            files_with_errors += 1
            error_listing += "  [%s]:\n" % path

            pairs = sorted(map(lambda t: (t[1], t[2]), triples),
                           key=lambda p: p[0])
            for line, msg in pairs:
                error_listing += col.red("    %4d: %s\n" % (line, msg))

        # Summarize errors
        summary = MSG_ERROR_SUMMARY % (len(all_errors), files_with_errors)
        print_highlight(summary)
        print(error_listing)
        sys.exit(1)
    else:
        print_success(MSG_CHECKS_PASSED)
sys.exit(0)
