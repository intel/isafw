#
# FSAPluginTestCase.py -  Test cases for FSA plugin, part of ISA FW
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

import unittest
import sys
from isafw import isafw
import isaplugins
import shutil
import os
import filecmp
import tarfile
import stat
from datetime import datetime

fsroot_path = "./fsa_plugin/data/rootfs"
unpack_path = "./fsa_plugin/data/"
ar_path = "./fsa_plugin/data/rootfs.tar.gz"
ref_fsa_problems_output = "./fsa_plugin/data/ref_fsa_problems_report_TestImage"
ref_fsa_full_output = "./fsa_plugin/data/ref_fsa_full_report_TestImage"
isafw_conf = isafw.ISA_config()
isafw_conf.reportdir = "./fsa_plugin/output"

class TestFSAPlugin(unittest.TestCase):

    def setUp(self):
        # cleaning up the report dir and creating it if needed
        if os.path.exists(os.path.dirname(isafw_conf.reportdir+"/internal/test")):
            shutil.rmtree(isafw_conf.reportdir)
        os.makedirs(os.path.dirname(isafw_conf.reportdir+"/internal/test"))
        # setting the timestamp
        isafw_conf.timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        # fetching proxy info
        isafw_conf.proxy = ""
        if "http_proxy" in os.environ:
            isafw_conf.proxy = os.environ['http_proxy']
        if "https_proxy" in os.environ:
            isafw_conf.proxy = os.environ['https_proxy']
        # unpack the rootfs for the test
        ar = tarfile.open(ar_path)
        ar.extractall(unpack_path)
        ar.close()
        # setup the permissions for the test, need to be root
        self.perms_setup(fsroot_path)
        isafw_conf.machine = "TestCaseMachine"
        isafw_conf.full_reports = True
        # creating ISA FW class
        self.imageSecurityAnalyser = isafw.ISA(isafw_conf)
        fs = isafw.ISA_filesystem()
        fs.img_name = "TestImage"
        fs.path_to_fs = fsroot_path
        self.imageSecurityAnalyser.process_filesystem(fs)

    def sortFile(self,file,fileName):
        f = open(file, "r")
        lines = [line for line in f if line.strip()]
        f.close()
        lines.sort()
        aux = open(isafw_conf.reportdir + '/' + fileName, "w")
        aux.writelines(lines)
        aux.close()

    def test_fsa_full_report(self):
        self.sortFile(isafw_conf.reportdir + "/fsa_full_report_" + isafw_conf.machine + "_" + isafw_conf.timestamp + "_TestImage",'sortedFSAFull')
        self.sortFile(ref_fsa_full_output,'sortedRefFSAFull')
        self.assertTrue(filecmp.cmp(isafw_conf.reportdir + '/sortedFSAFull',isafw_conf.reportdir + '/sortedRefFSAFull'),
                        'Output does not match')

    def test_fsa_problems_report(self):
        self.sortFile(isafw_conf.reportdir + "/fsa_problems_report_" + isafw_conf.machine + "_" + isafw_conf.timestamp + "_TestImage",'sortedFSAPbms')
        self.sortFile(ref_fsa_problems_output,'sortedRefFSAPbms')
        self.assertTrue(filecmp.cmp(isafw_conf.reportdir + '/sortedFSAPbms',isafw_conf.reportdir + '/sortedRefFSAPbms'),
                        'Output does not match')

    def perms_setup(self, fsroot_path):
        os.chmod(fsroot_path + "/file1", 0777)
        os.chown(fsroot_path + "/file2", 0, 0)
        os.chmod(fsroot_path + "/file2", 4775)
        os.chown(fsroot_path + "/file3", 0, 0)
        os.chmod(fsroot_path + "/file3", 0775)
        os.chmod(fsroot_path + "/file3", stat.S_ISGID)
        os.chmod(fsroot_path + "/file4", 2775)
        os.chmod(fsroot_path + "/file5", 0664)
        os.chmod(fsroot_path + "/file6", 0664)
        os.chmod(fsroot_path + "/file7", 0664)
        os.chmod(fsroot_path + "/file8", 0664)
        os.chmod(fsroot_path + "/file9", 0664)
        os.chmod(fsroot_path + "/file10", 0557)
        os.chmod(fsroot_path + "/file11", 0664)
        os.chmod(fsroot_path + "/dir1", 0777)
        os.chmod(fsroot_path + "/dir1",  stat.S_ISVTX)
        os.chmod(fsroot_path + "/dir2", 0777)
        os.chown(fsroot_path + "/dir2/file22", 0, 0)
        os.chmod(fsroot_path + "/dir2/file22", 4664)
 
if __name__ == '__main__':
    unittest.main()
