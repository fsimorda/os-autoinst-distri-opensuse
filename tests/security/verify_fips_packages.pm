# Copyright 2019-2020 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Compare FIPS package version with its expected version for SLE15SP4
# Maintainer: QE Security <none@suse.de>
# Tag: poo#125702

use base "basetest";
use strict;
use warnings;
use version;
use testapi;
use serial_terminal 'select_serial_terminal';
use utils qw(systemctl zypper_call);
use Mojo::Util 'trim';
use version_utils qw(is_rt is_sle);
use Utils::Architectures qw(is_s390x);

my $final_result = 'ok';
my $outfile = '/tmp/fips_packages_mismatch';

# Versions match the required packages for 15-SP4 which is certified.
# openssl3 is not tested in 15-SP4
my $kernel_ver = '5.14.21-150400.24.46.1';
my $kernelRT_ver = '5.14.21-150400.15.11.1';
my $openssl1_ver = '1.1.1l-150400.7.28.1';
my $gnutls_ver = '3.7.3-150400.4.35.1';
my $gcrypt_ver = '1.9.4-150400.6.8.1';
my $nss_ver = '3.79.4-150400.3.29.1';
my $ica_ver = '4.2.1-150400.3.8.1';
my $nettle_ver = '3.7.3-150400.2.21';
my $openssl3_ver = '';

if (is_sle('=15-SP6') || is_sle('=15-SP7')) {
    $kernel_ver = '6.4.0-150600.23.25.1';
    $kernelRT_ver = '6.4.0-150600.10.17.1';
    $openssl1_ver = '1.1.1w-150600.5.12.2';
    $openssl3_ver = '3.1.4-150600.5.15.1';
    $gnutls_ver = '3.8.3-150600.4.6.2';
    $gcrypt_ver = '1.10.3-150600.3.6.1';
    $nss_ver = '3.101.2-150400.3.54.1';
    $ica_ver = '4.3.1-150600.4.25.1';
    $nettle_ver = '3.9.1-150600.3.2.1';
}

my %packages_common = (
    'kernel-default' => $kernel_ver,
    'kernel-default-devel' => $kernel_ver,
    'kernel-devel' => $kernel_ver,
    'kernel-source' => $kernel_ver,
    'kernel-default-devel-debuginfo' => $kernel_ver,
    'kernel-default-debuginfo' => $kernel_ver,
    'kernel-default-debugsource' => $kernel_ver,
    'libopenssl1_1' => $openssl1_ver,
    'libopenssl1_1-hmac' => $openssl1_ver,
    'libopenssl1_1-32bit' => $openssl1_ver,
    'libopenssl1_1-hmac-32bit' => $openssl1_ver,
    libgnutls30 => $gnutls_ver,
    'libgnutls30-hmac' => $gnutls_ver,
    'libgnutls-devel' => $gnutls_ver,
    libnettle8 => $nettle_ver,
    libgcrypt20 => $gcrypt_ver,
    'libgcrypt20-hmac' => $gcrypt_ver,
    'libgcrypt-devel' => $gcrypt_ver,
    'mozilla-nss-tools' => $nss_ver,
    'mozilla-nss-debugsource' => $nss_ver,
    'mozilla-nss' => $nss_ver,
    'mozilla-nss-certs' => $nss_ver,
    'mozilla-nss-devel' => $nss_ver,
    'mozilla-nss-debuginfo' => $nss_ver
);

if (is_sle('=15-SP6') || (is_sle('=15-SP7'))) {
    $packages_common{'libopenssl-3-fips-provider'} = $openssl3_ver;
}

my %packages_s390x = (
    libica4 => $ica_ver,
    'libica-tools' => $ica_ver
);


my %packages_rt = (
    'kernel-rt' => $kernelRT_ver,
    'kernel-devel-rt' => $kernelRT_ver,
    'kernel-source-rt' => $kernelRT_ver
);


sub cmp_version {
    my ($old, $new) = @_;
    return $old eq $new;
}

sub cmp_packages {
    my ($package, $version) = @_;
    my $output = script_output("zypper se -xs $package | grep -w $package | head -1 | awk -F '|' '{print \$4}'", 100, proceed_on_failure => 1);
    my $out = '';
    for my $line (split(/\r?\n/, $output)) {
        if (trim($line) =~ m/^\d+\.\d+(\.\d+)?/) {
            $out = $line;
            if (!cmp_version($version, $out)) {
                $final_result = 'fail';
                record_info("Package version", "The $package version is $out, but request is $version", result => $final_result);
                assert_script_run "echo '$package:' >> $outfile";
                assert_script_run "echo ' found: $out' >> $outfile";
                assert_script_run "echo 'wanted: $version' >> $outfile";
                assert_script_run "echo >> $outfile";
            }
        }
    }
    if ($out eq '') {
        record_info("Package version", "The $package package does not exist", result => 'softfail');
        assert_script_run "echo '$package not found' >> $outfile";
        assert_script_run "echo >> $outfile";
    }
}

sub run {
    my $self = shift;

    select_serial_terminal;

    foreach my $key (keys %packages_common) {
        cmp_packages($key, $packages_common{$key});
    }

    if (is_s390x) {
        foreach my $key (keys %packages_s390x) {
            cmp_packages($key, $packages_s390x{$key});
        }
    }

    if (is_rt) {
        foreach my $key (keys %packages_rt) {
            cmp_packages($key, $packages_rt{$key});
        }
    }

    upload_asset $outfile;

    $self->result($final_result);
}

sub test_flags {
    return {fatal => 1};
}

1;
