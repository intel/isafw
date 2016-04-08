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

import unittest
import sys
sys.path.append("../isafw") 
import isafw
import shutil
import os
import filecmp
from datetime import datetime

kernel_conf = "./kca_plugin/data/config"
ref_kca_full_output = "./kca_plugin/data/ref_kca_full_report_TestImage"
ref_kca_problems_output = "./kca_plugin/data/ref_kca_problems_report_TestImage"
isafw_conf = isafw.ISA_config()
isafw_conf.reportdir = "./kca_plugin/output"

class TestKCAPlugin(unittest.TestCase):

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
        isafw_conf.full_reports = True
        # creating ISA FW class
        self.imageSecurityAnalyser = isafw.ISA(isafw_conf)
        kernel = isafw.ISA_kernel()
        kernel.img_name = "TestImage"
        kernel.path_to_config = kernel_conf
        self.imageSecurityAnalyser.process_kernel(kernel)

    def sortFile(self,file,fileName):
        f = open(file, "r")
        lines = [line for line in f if line.strip()]
        f.close()
        lines.sort()
        aux = open(isafw_conf.reportdir + '/' + fileName, "w")
        aux.writelines(lines)
        aux.close()       

    def test_kca_full_report(self):
        self.sortFile(isafw_conf.reportdir + "/kca_full_report_TestImage_" + isafw_conf.timestamp,'sortedKCAFull')
        self.sortFile(ref_kca_full_output, 'sortedRefKCAFull')
        self.assertTrue(filecmp.cmp(isafw_conf.reportdir + '/sortedKCAFull',isafw_conf.reportdir + '/sortedRefKCAFull'),
                        'Output does not match')

    def test_kca_problems_report(self):
        self.sortFile(isafw_conf.reportdir + "/kca_problems_report_TestImage_" + isafw_conf.timestamp,'sortedKCAPbms')
        self.sortFile(ref_kca_problems_output,'sortedRefKCAPbms')
        self.assertTrue(filecmp.cmp(isafw_conf.reportdir + '/sortedKCAPbms',isafw_conf.reportdir + '/sortedRefKCAPbms'),
                        'Output does not match')
 
if __name__ == '__main__':
    unittest.main()
