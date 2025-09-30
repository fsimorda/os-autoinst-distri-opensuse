# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Package: gnutls / libnettle
# Summary: SLES15SP2 and SLES15SP4 FIPS certification need to certify gnutls and libnettle
#          In this case, will do some base check for gnutls
#
# Maintainer: QE Security <none@suse.de>

from testapi import *
import re

perl.require("version_utils")
perl.require("serial_terminal")
perl.require("utils")
perl.require("power_action_utils")
perl.require("transactional")

def install_gnutls(self):
    "Install the gnutls / libnettle packages (pulled as dependency)"
    if (perl.version_utils.is_transactional()):
        perl.transactional.trup_call("pkg install gnutls")
    else:
        perl.utils.zypper_call("in gnutls")

    current_ver = script_output("rpm -q --qf '%{version}\\n' gnutls")
    record_info("gnutls version", "Version of Current gnutls package: " + current_ver)
    # gnutls attempt to update to 3.7.2+ in SLE15 SP4 base on the feature
    # SLE-19765: Update libnettle and gnutls to new major versions
    # starting with gnu nettle 3.6+: Support for ED448 signature

    if (perl.version_utils.is_sle(">15-SP4")) or (perl.version_utils.is_leap(">15-SP4")):
        assert_script_run("gnutls-cli --list | grep -w SIGN-EdDSA-Ed448")

def validate_gnutls(self):
     """ Check the library is in FIPS kernel mode, and skip checking this in FIPS ENV mode
     Since ENV mode is not pulled out/installed the fips library """

     if not (get_var("FIPS_ENV_MODE")):
         output = script_output("gnutls-cli --fips140-mode 2>&1")
         record_info("gnutls FIPS mode: ", output)

     assert_script_run("gnutls-cli -l | grep \"Certificate types\" | grep \"CTYPE-X.509\"")

     # Lists all ciphers, check the certificate types and double confirm TLS1.3,DTLS1.2 and SSL3.0
     if (perl.version_utils.is_tumbleweed):
         re_proto = "grep -e VERS-TLS1.2 -e VERS-TLS1.3 -e VERS-DTLS1.2"
     else:
         re_proto = "grep -e VERS-SSL3.0 -e VERS-TLS1.3 -e VERS-DTLS1.2"
     assert_script_run("gnutls-cli -l | grep Protocols | + ", re_proto)

def validate(self):
    """Check google's imap server and verify basic function"""
    
    validate_script_output('echo | gnutls-cli -d 1 imap.gmail.com -p 993', lambda x: re.match(r"Certificate\stype:\sX\.509.*\nStatus:\sThe\scertificate\sis\strusted.*\nDescription:\s\(TLS1\.3.*\).*\nHandshake\swas\scompleted.*", x))

def run(self):
    perl.serial_terminal.select_serial_terminal()

    self.install_gnutls()

    self.validate_gnutls()
