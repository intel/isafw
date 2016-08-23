#
# KCAPluginTestCase.py -  Test cases for KCA plugin, part of ISA FW
#
# Copyright (c) 2015, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of Intel Corporation nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
import os
import sys
import unittest
from datetime import datetime

from isafw import isafw

PWD = sys.path[0]  # directory this test script is executing in
KERNEL_CONFIGS = {"x86": os.path.join(PWD, "kca_plugin", "data", "x86_config"),
                  "arm": os.path.join(PWD, "kca_plugin", "data", "arm_config")}

TIMESTAMP = datetime.now().strftime('%Y%m%d%H%M%S')
OUTPUT_DIR = os.path.join(PWD, "kca_plugin", "output_{}".format(TIMESTAMP))

IMAGE_NAME = "TestImage"


class TestKCAPlugin(unittest.TestCase):
    isafw_conf = None

    @classmethod
    def setUpClass(cls):
        # one-time setup for ISA config which doesn't change between testcases
        cls.isafw_conf = isafw.ISA_config()
        cls.isafw_conf.timestamp = TIMESTAMP

        if "https_proxy" in os.environ:
            cls.isafw_conf.proxy = os.environ['https_proxy']
        elif "http_proxy" in os.environ:
            cls.isafw_conf.proxy = os.environ['http_proxy']

        cls.isafw_conf.full_reports = True

    def setUp(self):
        # create a directory for each testcase
        testcase_dir = os.path.join(OUTPUT_DIR, self.id())
        if not os.path.exists(testcase_dir):
            os.makedirs(testcase_dir)

        self.isafw_conf.reportdir = testcase_dir
        self.isafw_conf.logdir = testcase_dir

    def generateReport(self, arch):
        self.isafw_conf.arch = arch
        self.isafw_conf.machine = arch
        # instantiate ISA FW class and generate a report
        image_security_analyzer = isafw.ISA(self.isafw_conf)
        kernel = isafw.ISA_kernel()
        kernel.img_name = IMAGE_NAME
        kernel.path_to_config = KERNEL_CONFIGS[arch]
        image_security_analyzer.process_kernel(kernel)

    def getReportFilePath(self, report_type):
        # calculate the report file path based on current isafw conf
        report_name = "_".join((report_type, self.isafw_conf.machine, self.isafw_conf.timestamp, IMAGE_NAME))
        return os.path.join(self.isafw_conf.reportdir, report_name)

    def readReport(self, report_name):
        # read report from disk and parse it into a dictionary
        output_dict = {}
        with open(self.getReportFilePath(report_name), "r") as f:
            for line in f:
                tokens = line.strip().split(":")
                if len(tokens) < 2:
                    continue
                key = tokens[0].strip()
                value = tokens[1].strip()
                if len(key) < 1 or len(value) < 1:
                    continue
                output_dict[key] = value

        return output_dict

    def validateReportOnArch(self, arch, report, expected_unfiltered):
        # filter expected values for relevant architecture
        expected = {}
        for key, value in expected_unfiltered.iteritems():
            if isinstance(value, dict):
                if arch in value:
                    expected[key] = value[arch]
            else:
                expected[key] = value

        self.generateReport(arch)
        actual = self.readReport(report)
        self.assertDictContainsSubset(expected, actual)

    def validateReportOnAllArch(self, report, expected):
        self.validateReportOnArch("x86", report, expected)
        self.validateReportOnArch("arm", report, expected)

    def test_kca_hardening_options(self):
        expected = {'CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE': 'y',
                    'CONFIG_ARCH_HAS_DEBUG_STRICT_USER_COPY_CHECKS': {'x86':'y', 'arm':'not set'},
                    'CONFIG_BINFMT_MISC': {'x86':'m', 'arm':'not set'},
                    'CONFIG_BPF_JIT': 'not set',
                    'CONFIG_BUG': 'y',
                    'CONFIG_CC_STACKPROTECTOR': 'not set',
                    'CONFIG_CHECKPOINT_RESTORE': 'not set',
                    'CONFIG_CMDLINE': {'x86':'not set', 'arm':'" debug"'},
                    'CONFIG_CMDLINE_BOOL': 'not set',
                    'CONFIG_CMDLINE_OVERRIDE': 'not set',
                    'CONFIG_COREDUMP': 'y',
                    'CONFIG_CROSS_MEMORY_ATTACH': 'y',
                    'CONFIG_DEBUG_BUGVERBOSE': 'y',
                    'CONFIG_DEBUG_FS': {'x86':'y', 'arm':'not set'},
                    'CONFIG_DEBUG_INFO': {'x86':'y', 'arm':'not set'},
                    'CONFIG_DEBUG_KERNEL': 'y',
                    'CONFIG_DEBUG_RODATA': {'x86':'y', 'arm':'not set'},
                    'CONFIG_DEBUG_STACKOVERFLOW': 'not set',
                    'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS': 'not set',
                    'CONFIG_DEFAULT_MMAP_MIN_ADDR': {'x86':'4096'},
                    'CONFIG_DEVKMEM': 'y',
                    'CONFIG_DEVMEM': 'not set',
                    'CONFIG_FTRACE': 'y',
                    'CONFIG_FW_LOADER_USER_HELPER': {'x86':'not set', 'arm':'y'},
                    'CONFIG_IKCONFIG': 'y',
                    'CONFIG_IKCONFIG_PROC': 'y',
                    'CONFIG_IP_PNP': 'y',
                    'CONFIG_KALLSYMS': 'y',
                    'CONFIG_KALLSYMS_ALL': {'x86':'y', 'arm':'not set'},
                    'CONFIG_KEXEC': {'x86':'not set', 'arm':'y'},
                    'CONFIG_KGDB': {'x86':'y', 'arm':'not set'},
                    'CONFIG_KPROBES': {'x86':'y', 'arm':'not set'},
                    'CONFIG_MAGIC_SYSRQ': {'x86':'y', 'arm':'not set'},
                    'CONFIG_MODULE_FORCE_LOAD': 'not set',
                    'CONFIG_MODULE_SIG_FORCE': 'not set',
                    'CONFIG_MODULE_UNLOAD': 'y',
                    'CONFIG_NAMESPACES': 'y',
                    'CONFIG_NFSD': 'not set',
                    'CONFIG_NFS_FS': 'y',
                    'CONFIG_OPROFILE': {'x86':'y', 'arm':'not set'},
                    'CONFIG_PACKET_DIAG': 'not set',
                    'CONFIG_PANIC_ON_OOPS': 'not set',
                    'CONFIG_PROC_KCORE': {'x86':'y', 'arm':'not set'},
                    'CONFIG_PROFILING': {'x86':'y', 'arm':'not set'},
                    'CONFIG_RANDOMIZE_BASE': 'not set',
                    'CONFIG_RANDOMIZE_BASE_MAX_OFFSET': {'x86':'not set'},
                    'CONFIG_SECURITY_DMESG_RESTRICT': 'not set',
                    'CONFIG_SERIAL_8250_CONSOLE': 'y',
                    'CONFIG_SERIAL_CORE': 'y',
                    'CONFIG_SERIAL_CORE_CONSOLE': 'y',
                    'CONFIG_STRICT_DEVMEM': 'not set',
                    'CONFIG_SWAP': 'y',
                    'CONFIG_SYSCTL_SYSCALL': {'x86':'not set', 'arm':'y'},
                    'CONFIG_UNIX_DIAG': 'not set',
                    'CONFIG_USELIB': {'x86':'y', 'arm':'not set'},
                    'CONFIG_X86_INTEL_MPX': {'x86':'not set'},
                    'CONFIG_X86_MSR': {'x86':'y'}}
        self.validateReportOnAllArch("kca_full_report", expected)

    def test_kca_key_options(self):
        expected = {'CONFIG_ENCRYPTED_KEYS': {'x86':'y', 'arm':'not set'},
                    'CONFIG_KEYS': 'y',
                    'CONFIG_KEYS_DEBUG_PROC_KEYS': {'x86':'y', 'arm':'not set'},
                    'CONFIG_TRUSTED_KEYS': {'x86':'y', 'arm':'not set'}}
        self.validateReportOnAllArch("kca_full_report", expected)

    def test_kca_security_options(self):
        expected = {'CONFIG_DEFAULT_SECURITY': {'x86':'"smack"', 'arm':'""'},
                    'CONFIG_INTEL_TXT': {'x86':'not set'},
                    'CONFIG_LSM_MMAP_MIN_ADDR': {'x86': 'not set'},
                    'CONFIG_SECURITY': {'x86':'y', 'arm':'not set'},
                    'CONFIG_SECURITYFS': {'x86':'y', 'arm':'not set'},
                    'CONFIG_SECURITY_APPARMOR': 'not set',
                    'CONFIG_SECURITY_NETWORKING': 'not set',
                    'CONFIG_SECURITY_SELINUX': 'not set',
                    'CONFIG_SECURITY_SMACK': {'x86':'y', 'arm':'not set'},
                    'CONFIG_SECURITY_TOMOYO': 'not set',
                    'CONFIG_SECURITY_YAMA': 'not set',
                    'CONFIG_SECURITY_YAMA_STACKED': 'not set'}
        self.validateReportOnAllArch("kca_full_report", expected)

    def test_kca_integrity_options(self):

        expected = {'CONFIG_EVM': {'x86':'y', 'arm':'not set'},
                    'CONFIG_EVM_ATTR_FSUUID': {'x86':'y', 'arm':'not set'},
                    'CONFIG_EVM_EXTRA_SMACK_XATTRS': {'x86':'y', 'arm':'not set'},
                    'CONFIG_IMA': {'x86':'y', 'arm':'not set'},
                    'CONFIG_IMA_APPRAISE': {'x86':'y', 'arm':'not set'},
                    'CONFIG_IMA_APPRAISE_SIGNED_INIT': 'not set',
                    'CONFIG_IMA_DEFAULT_HASH_SHA1': {'x86':'y', 'arm':'not set'},
                    'CONFIG_IMA_DEFAULT_HASH_SHA256': 'not set',
                    'CONFIG_IMA_DEFAULT_HASH_SHA512': 'not set',
                    'CONFIG_IMA_DEFAULT_HASH_WP512': 'not set',
                    'CONFIG_IMA_LSM_RULES': 'not set',
                    'CONFIG_IMA_TRUSTED_KEYRING': {'x86':'y', 'arm':'not set'},
                    'CONFIG_INTEGRITY': {'x86':'y', 'arm':'not set'},
                    'CONFIG_INTEGRITY_AUDIT': 'not set',
                    'CONFIG_INTEGRITY_SIGNATURE': {'x86':'y', 'arm':'not set'}}
        self.validateReportOnAllArch("kca_full_report", expected)

    def test_kca_hardening_problem_report(self):
        expected = {'CONFIG_ARCH_HAS_DEBUG_STRICT_USER_COPY_CHECKS' :  {'arm' : 'y'},
                    'CONFIG_BINFMT_MISC' :  {'x86' : 'not set'},
                    'CONFIG_BUG' :  'not set',
                    'CONFIG_CC_STACKPROTECTOR' :  'y',
                    'CONFIG_CMDLINE_BOOL' :  'y',
                    'CONFIG_CMDLINE_OVERRIDE' :  'y',
                    'CONFIG_COREDUMP' :  'not set',
                    'CONFIG_CROSS_MEMORY_ATTACH' :  'not set',
                    'CONFIG_DEBUG_BUGVERBOSE' :  'not set',
                    'CONFIG_DEBUG_FS' :  {'x86' : 'not set'},
                    'CONFIG_DEBUG_INFO' :  {'x86' : 'not set'},
                    'CONFIG_DEBUG_KERNEL' :  'not set',
                    'CONFIG_DEBUG_RODATA' :  {'arm' : 'y'},
                    'CONFIG_DEBUG_STACKOVERFLOW' :  'y',
                    'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS' :  {'arm' : 'y'},
                    'CONFIG_DEFAULT_MMAP_MIN_ADDR' :  {'x86' : '65536', 'arm' : '32768'},
                    'CONFIG_DEVKMEM' :  'not set',
                    'CONFIG_FTRACE' :  'not set',
                    'CONFIG_FW_LOADER_USER_HELPER' :  {'arm' : 'not set'},
                    'CONFIG_IKCONFIG' :  'not set',
                    'CONFIG_IKCONFIG_PROC' :  'not set',
                    'CONFIG_IP_PNP' :  'not set',
                    'CONFIG_KALLSYMS' :  'not set',
                    'CONFIG_KALLSYMS_ALL' :  {'x86' : 'not set'},
                    'CONFIG_KGDB' :  {'x86' : 'not set'},
                    'CONFIG_KPROBES' :  {'x86' : 'not set'},
                    'CONFIG_MAGIC_SYSRQ' :  {'x86' : 'not set'},
                    'CONFIG_KEXEC' :  {'arm' : 'not set'},
                    'CONFIG_MODULE_SIG_FORCE' :  'y',
                    'CONFIG_MODULE_UNLOAD' :  'not set',
                    'CONFIG_NAMESPACES' :  'not set',
                    'CONFIG_NFS_FS' :  'not set',
                    'CONFIG_OPROFILE' :  {'x86' : 'not set'},
                    'CONFIG_PANIC_ON_OOPS' :  'y',
                    'CONFIG_PROC_KCORE' :  {'x86' : 'not set'},
                    'CONFIG_PROFILING' :  {'x86' : 'not set'},
                    'CONFIG_RANDOMIZE_BASE' :  'y',
                    'CONFIG_RANDOMIZE_BASE_MAX_OFFSET' :  {'x86' :  '0x20000000,0x40000000'},
                    'CONFIG_SECURITY_DMESG_RESTRICT' :  'y',
                    'CONFIG_SERIAL_8250_CONSOLE' :  'not set',
                    'CONFIG_SERIAL_CORE' :  'not set',
                    'CONFIG_SERIAL_CORE_CONSOLE' :  'not set',
                    'CONFIG_STRICT_DEVMEM' :  'y',
                    'CONFIG_SWAP' :  'not set',
                    'CONFIG_SYSCTL_SYSCALL' :  {'arm' : 'not set'},
                    'CONFIG_ENCRYPTED_KEYS' :  {'arm' : 'y'},
                    'CONFIG_TRUSTED_KEYS' :  {'arm' : 'y'},
                    'CONFIG_USELIB' :  {'x86' : 'not set'},
                    'CONFIG_X86_INTEL_MPX' :  {'x86' : 'y'},
                    'CONFIG_X86_MSR' :  {'x86' : 'not set'}}
        self.validateReportOnAllArch("kca_problems_report", expected)

    def test_kca_key_problem_report(self):
        expected = {'CONFIG_KEYS_DEBUG_PROC_KEYS': {'x86':'not set'},
                    'CONFIG_ENCRYPTED_KEYS' : {'arm':'y'},
                    'CONFIG_TRUSTED_KEYS' : {'arm':'y'}
                   }
        self.validateReportOnAllArch("kca_problems_report", expected)

    def test_kca_security_problem_report(self):
        expected = {'CONFIG_DEFAULT_SECURITY' : {'arm':'"selinux","smack","apparmor","tomoyo"'},
                    'CONFIG_INTEL_TXT': {'x86':'y'},
                    'CONFIG_LSM_MMAP_MIN_ADDR': {'x86': '65536', 'arm':'32768'},
                    'CONFIG_SECURITY' : {'arm':'y'},
                    'CONFIG_SECURITYFS' : {'arm':'y'},
                    'CONFIG_SECURITY_APPARMOR' : {'arm':'y'},
                    'CONFIG_SECURITY_NETWORKING' : {'arm':'y'},
                    'CONFIG_SECURITY_SELINUX' : {'arm':'y'},
                    'CONFIG_SECURITY_SMACK' : {'arm':'y'},
                    'CONFIG_SECURITY_TOMOYO' : {'arm':'y'},
                    'CONFIG_SECURITY_NETWORKING': 'y',
                    'CONFIG_SECURITY_YAMA': 'y',
                    'CONFIG_SECURITY_YAMA_STACKED': 'y'}
        self.validateReportOnAllArch("kca_problems_report", expected)

    def test_kca_integrity_problem_report(self):
        expected = {'CONFIG_EVM' : {'arm':'y'},
                    'CONFIG_EVM_ATTR_FSUUID' : {'arm':'y'},
                    'CONFIG_EVM_EXTRA_SMACK_XATTRS' : {'arm':'y'},
                    'CONFIG_IMA' : {'arm':'y'},
                    'CONFIG_IMA_APPRAISE' : {'arm':'y'},
                    'CONFIG_IMA_TRUSTED_KEYRING' : {'arm':'y'},
                    'CONFIG_INTEGRITY' : {'arm':'y'},
                    'CONFIG_INTEGRITY_AUDIT' : {'arm':'y'},
                    'CONFIG_INTEGRITY_SIGNATURE' : {'arm':'y'},
                    'CONFIG_IMA_APPRAISE_SIGNED_INIT': 'y',
                    'CONFIG_IMA_DEFAULT_HASH_SHA1': {'x86':'not set'},
                    'CONFIG_IMA_DEFAULT_HASH_SHA256': 'y',
                    'CONFIG_IMA_DEFAULT_HASH_SHA512': 'y',
                    'CONFIG_IMA_LSM_RULES': 'y',
                    'CONFIG_INTEGRITY_AUDIT': 'y'}
        self.validateReportOnAllArch("kca_problems_report", expected)


if __name__ == '__main__':
    unittest.main()
