# vim: set syntax=python ts=4 :
#
# Copyright (c) 2018-2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

import os
import logging
import pathlib
import shutil
import subprocess
import glob
import re

logger = logging.getLogger('twister')
logger.setLevel(logging.DEBUG)

class CoverageTool:
    """ Base class for every supported coverage tool
    """

    def __init__(self):
        self.gcov_tool = None
        self.base_dir = None
        self.output_formats = None

    @staticmethod
    def factory(tool):
        if tool == 'lcov':
            t =  Lcov()
        elif tool == 'gcovr':
            t =  Gcovr()
        else:
            logger.error("Unsupported coverage tool specified: {}".format(tool))
            return None

        logger.debug(f"Select {tool} as the coverage tool...")
        return t

    @staticmethod
    def retrieve_gcov_data(input_file):
        logger.debug("Working on %s" % input_file)
        extracted_coverage_info = {}
        capture_data = False
        capture_complete = False
        with open(input_file, 'r') as fp:
            for line in fp.readlines():
                if re.search("GCOV_COVERAGE_DUMP_START", line):
                    capture_data = True
                    continue
                if re.search("GCOV_COVERAGE_DUMP_END", line):
                    capture_complete = True
                    break
                # Loop until the coverage data is found.
                if not capture_data:
                    continue
                if line.startswith("*"):
                    sp = line.split("<")
                    if len(sp) > 1:
                        # Remove the leading delimiter "*"
                        file_name = sp[0][1:]
                        # Remove the trailing new line char
                        hex_dump = sp[1][:-1]
                    else:
                        continue
                else:
                    continue
                extracted_coverage_info.update({file_name: hex_dump})
        if not capture_data:
            capture_complete = True
        return {'complete': capture_complete, 'data': extracted_coverage_info}

    @staticmethod
    def create_gcda_files(extracted_coverage_info):
        gcda_created = True
        logger.debug("Generating gcda files")
        for filename, hexdump_val in extracted_coverage_info.items():
            # if kobject_hash is given for coverage gcovr fails
            # hence skipping it problem only in gcovr v4.1
            if "kobject_hash" in filename:
                filename = (filename[:-4]) + "gcno"
                try:
                    os.remove(filename)
                except Exception:
                    pass
                continue

            try:
                with open(filename, 'wb') as fp:
                    fp.write(bytes.fromhex(hexdump_val))
            except ValueError:
                logger.exception("Unable to convert hex data for file: {}".format(filename))
                gcda_created = False
            except FileNotFoundError:
                logger.exception("Unable to create gcda file: {}".format(filename))
                gcda_created = False
        return gcda_created

    def generate(self, outdir):
        coverage_completed = True
        for filename in glob.glob("%s/**/handler.log" % outdir, recursive=True):
            gcov_data = self.__class__.retrieve_gcov_data(filename)
            capture_complete = gcov_data['complete']
            extracted_coverage_info = gcov_data['data']
            if capture_complete:
                gcda_created = self.__class__.create_gcda_files(extracted_coverage_info)
                if gcda_created:
                    logger.debug("Gcov data captured: {}".format(filename))
                else:
                    logger.error("Gcov data invalid for: {}".format(filename))
                    coverage_completed = False
            else:
                logger.error("Gcov data capture incomplete: {}".format(filename))
                coverage_completed = False

        with open(os.path.join(outdir, "coverage.log"), "a") as coveragelog:
            ret = self._generate(outdir, coveragelog)
            if ret == 0:
                report_log = {
                    "html": "HTML report generated: {}".format(os.path.join(outdir, "coverage", "index.html")),
                    "lcov": "LCOV report generated: {}".format(os.path.join(outdir, "coverage.info")),
                    "xml": "XML report generated: {}".format(os.path.join(outdir, "coverage", "coverage.xml")),
                    "csv": "CSV report generated: {}".format(os.path.join(outdir, "coverage", "coverage.csv")),
                    "txt": "TXT report generated: {}".format(os.path.join(outdir, "coverage", "coverage.txt")),
                    "coveralls": "Coveralls report generated: {}".format(os.path.join(outdir, "coverage", "coverage.coveralls.json")),
                    "sonarqube": "Sonarqube report generated: {}".format(os.path.join(outdir, "coverage", "coverage.sonarqube.xml"))
                }
                for r in self.output_formats.split(','):
                    logger.info(report_log[r])
            else:
                coverage_completed = False
        logger.debug("All coverage data processed: {}".format(coverage_completed))
        return coverage_completed


class Lcov(CoverageTool):

    def __init__(self):
        super().__init__()
        self.ignores = []
        self.output_formats = "lcov,html"
        self.version = self.get_version()

    def get_version(self):
        try:
            result = subprocess.run(['lcov', '--version'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True, check=True)
            version_output = result.stdout.strip().replace('lcov: LCOV version ', '')
            return version_output
        except subprocess.CalledProcessError as e:
            logger.error(f"Unsable to determine lcov version: {e}")

        return ""

    def add_ignore_file(self, pattern):
        self.ignores.append('*' + pattern + '*')

    def add_ignore_directory(self, pattern):
        self.ignores.append('*/' + pattern + '/*')

    @staticmethod
    def run_command(cmd, coveragelog):
        cmd_str = " ".join(cmd)
        logger.debug(f"Running {cmd_str}...")
        return subprocess.call(cmd, stdout=coveragelog)

    def _generate(self, outdir, coveragelog):
        coveragefile = os.path.join(outdir, "coverage.info")
        ztestfile = os.path.join(outdir, "ztest.info")
        if self.version.startswith("2"):
            branch_coverage = "branch_coverage=1"
            ignore_errors = [
                         "--ignore-errors", "inconsistent,inconsistent",
                         "--ignore-errors", "negative,negative",
                         "--ignore-errors", "unused,unused",
                         "--ignore-errors", "empty,empty",
                         "--ignore-errors", "mismatch,mismatch"
                         ]
        else:
            branch_coverage = "lcov_branch_coverage=1"
            ignore_errors = []

        cmd = ["lcov", "--gcov-tool", str(self.gcov_tool),
                         "--capture", "--directory", outdir,
                         "--rc", branch_coverage,
                         "--output-file", coveragefile]
        cmd = cmd + ignore_errors
        self.run_command(cmd, coveragelog)
        # We want to remove tests/* and tests/ztest/test/* but save tests/ztest
        cmd = ["lcov", "--gcov-tool", self.gcov_tool, "--extract",
                         coveragefile,
                         os.path.join(self.base_dir, "tests", "ztest", "*"),
                         "--output-file", ztestfile,
                         "--rc", branch_coverage]

        cmd = cmd + ignore_errors
        self.run_command(cmd, coveragelog)

        if os.path.exists(ztestfile) and os.path.getsize(ztestfile) > 0:
            cmd = ["lcov", "--gcov-tool", self.gcov_tool, "--remove",
                             ztestfile,
                             os.path.join(self.base_dir, "tests/ztest/test/*"),
                             "--output-file", ztestfile,
                             "--rc", branch_coverage]
            cmd = cmd + ignore_errors
            self.run_command(cmd, coveragelog)

            files = [coveragefile, ztestfile]
        else:
            files = [coveragefile]

        for i in self.ignores:
            cmd = ["lcov", "--gcov-tool", self.gcov_tool, "--remove",
                 coveragefile, i,
                 "--output-file", coveragefile,
                 "--rc", branch_coverage]
            cmd = cmd + ignore_errors
            self.run_command(cmd, coveragelog)

        if 'html' not in self.output_formats.split(','):
            return 0

        # The --ignore-errors source option is added to avoid it exiting due to
        # samples/application_development/external_lib/
        cmd = ["genhtml", "--legend", "--branch-coverage",
                                "--prefix", self.base_dir,
                                "-output-directory",
                                os.path.join(outdir, "coverage")] + files
        cmd = cmd + ignore_errors
        return self.run_command(cmd, coveragelog)


class Gcovr(CoverageTool):

    def __init__(self):
        super().__init__()
        self.ignores = []
        self.output_formats = "html"

    def add_ignore_file(self, pattern):
        self.ignores.append('.*' + pattern + '.*')

    def add_ignore_directory(self, pattern):
        self.ignores.append(".*/" + pattern + '/.*')

    @staticmethod
    def _interleave_list(prefix, list):
        tuple_list = [(prefix, item) for item in list]
        return [item for sublist in tuple_list for item in sublist]

    @staticmethod
    def _flatten_list(list):
        return [a for b in list for a in b]

    def _generate(self, outdir, coveragelog):
        coveragefile = os.path.join(outdir, "coverage.json")
        ztestfile = os.path.join(outdir, "ztest.json")

        excludes = Gcovr._interleave_list("-e", self.ignores)

        # Different ifdef-ed implementations of the same function should not be
        # in conflict treated by GCOVR as separate objects for coverage statistics.
        mode_options = ["--merge-mode-functions=separate"]

        # We want to remove tests/* and tests/ztest/test/* but save tests/ztest
        cmd = ["gcovr", "-r", self.base_dir,
               "--gcov-ignore-parse-errors=negative_hits.warn_once_per_file",
               "--gcov-executable", str(self.gcov_tool),
               "-e", "tests/*"]
        cmd += excludes + mode_options + ["--json", "-o", coveragefile, outdir]
        cmd_str = " ".join(cmd)
        logger.debug(f"Running {cmd_str}...")
        subprocess.call(cmd, stdout=coveragelog)

        subprocess.call(["gcovr", "-r", self.base_dir, "--gcov-executable",
                         self.gcov_tool, "-f", "tests/ztest", "-e",
                         "tests/ztest/test/*", "--json", "-o", ztestfile,
                         outdir] + mode_options, stdout=coveragelog)

        if os.path.exists(ztestfile) and os.path.getsize(ztestfile) > 0:
            files = [coveragefile, ztestfile]
        else:
            files = [coveragefile]

        subdir = os.path.join(outdir, "coverage")
        os.makedirs(subdir, exist_ok=True)

        tracefiles = self._interleave_list("--add-tracefile", files)

        # Convert command line argument (comma-separated list) to gcovr flags
        report_options = {
            "html": ["--html", os.path.join(subdir, "index.html"), "--html-details"],
            "xml": ["--xml", os.path.join(subdir, "coverage.xml"), "--xml-pretty"],
            "csv": ["--csv", os.path.join(subdir, "coverage.csv")],
            "txt": ["--txt", os.path.join(subdir, "coverage.txt")],
            "coveralls": ["--coveralls", os.path.join(subdir, "coverage.coveralls.json"), "--coveralls-pretty"],
            "sonarqube": ["--sonarqube", os.path.join(subdir, "coverage.sonarqube.xml")]
        }
        gcovr_options = self._flatten_list([report_options[r] for r in self.output_formats.split(',')])

        return subprocess.call(["gcovr", "-r", self.base_dir] + mode_options + gcovr_options + tracefiles,
                               stdout=coveragelog)



def run_coverage(testplan, options):
    use_system_gcov = False

    for plat in options.coverage_platform:
        _plat = testplan.get_platform(plat)
        if _plat and (_plat.type in {"native", "unit"}):
            use_system_gcov = True
    if not options.gcov_tool:
        zephyr_sdk_gcov_tool = os.path.join(
            os.environ.get("ZEPHYR_SDK_INSTALL_DIR", default=""),
            "x86_64-zephyr-elf/bin/x86_64-zephyr-elf-gcov")
        if os.environ.get("ZEPHYR_TOOLCHAIN_VARIANT") == "llvm":
            llvm_path = os.environ.get("LLVM_TOOLCHAIN_PATH")
            if llvm_path is not None:
                llvm_path = os.path.join(llvm_path, "bin")
            llvm_cov = shutil.which("llvm-cov", path=llvm_path)
            llvm_cov_ext = pathlib.Path(llvm_cov).suffix
            gcov_lnk = os.path.join(options.outdir, f"gcov{llvm_cov_ext}")
            try:
                os.symlink(llvm_cov, gcov_lnk)
            except OSError:
                shutil.copy(llvm_cov, gcov_lnk)
            options.gcov_tool = gcov_lnk
        elif use_system_gcov:
            options.gcov_tool = "gcov"
        elif os.path.exists(zephyr_sdk_gcov_tool):
            options.gcov_tool = zephyr_sdk_gcov_tool

    logger.info("Generating coverage files...")
    coverage_tool = CoverageTool.factory(options.coverage_tool)
    coverage_tool.gcov_tool = options.gcov_tool
    coverage_tool.base_dir = os.path.abspath(options.coverage_basedir)
    # Apply output format default
    if options.coverage_formats is not None:
        coverage_tool.output_formats = options.coverage_formats
    coverage_tool.add_ignore_file('generated')
    coverage_tool.add_ignore_directory('tests')
    coverage_tool.add_ignore_directory('samples')
    coverage_completed = coverage_tool.generate(options.outdir)
    return coverage_completed
