#
# CFAPluginTestCase.py -  Test cases for CFA plugin, part of ISA FW
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
sys.path.append("../isafw") 
import isafw
import shutil
import os
import filecmp
import tarfile
from datetime import datetime

fsroot_tar = "./cfa_plugin/data/rootfs.tar.gz"
fsroot_path = "./cfa_plugin/data/rootfs"
ref_cfa_full_output = "./cfa_plugin/data/ref_cfa_full_report_TestImage"
ref_cfa_problems_output = "./cfa_plugin/data/ref_cfa_problems_report_TestImage"
isafw_conf = isafw.ISA_config()
isafw_conf.reportdir = "./cfa_plugin/output"

class TestCFAPlugin(unittest.TestCase):

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
        # unpacking rootfs
        fsroot_arch = tarfile.open(name=fsroot_tar, mode='r')
        fsroot_arch.extractall(path=fsroot_path, members=None)
        isafw_conf.machine = "TestCaseMachine"
        isafw_conf.full_reports = True
        # creating ISA FW class
        self.imageSecurityAnalyser = isafw.ISA(isafw_conf)
        fs = isafw.ISA_filesystem()
        fs.img_name = "TestImage"
        fs.path_to_fs = fsroot_path
        self.imageSecurityAnalyser.process_filesystem(fs)

    def tearDown(self):
        if os.path.exists(os.path.dirname(fsroot_path +"/test")):
            shutil.rmtree(fsroot_path)
        os.makedirs(os.path.dirname(fsroot_path+"/test"))

    def sortFile(self,file,fileName):
        f = open(file, "r")
        lines = [line for line in f if line.strip()]
        f.close()
        lines.sort()
        aux = open(isafw_conf.reportdir + '/' + fileName, "w")
        aux.writelines(lines)
        aux.close()       

    def test_cfa_full_report(self):
        self.sortFile(isafw_conf.reportdir + "/cfa_full_report_" + isafw_conf.machine + "_" + isafw_conf.timestamp + "_TestImage",'sortedCFAFull')
        self.sortFile(ref_cfa_full_output,'sortedRefCFAFull')
        self.assertTrue(filecmp.cmp(isafw_conf.reportdir + '/sortedCFAFull',isafw_conf.reportdir + '/sortedRefCFAFull'),
                        'Output does not match')

    def test_cfa_problems_report(self):
        self.sortFile(isafw_conf.reportdir + "/cfa_problems_report_" + isafw_conf.machine + "_" + isafw_conf.timestamp + "_TestImage",'sortedCFAPbms')
        self.sortFile(ref_cfa_problems_output,'sortedRefCFAPbms')
        self.assertTrue(filecmp.cmp(isafw_conf.reportdir + '/sortedCFAPbms',isafw_conf.reportdir + '/sortedRefCFAPbms'),
                        'Output does not match')

if __name__ == '__main__':
    unittest.main()
