# Copyright 2019-2020 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Compare FIPS package version with its expected version for SLE15SP4
# Maintainer: QE Security <none@suse.de>
# Tag: poo#125702

use base "basetest";
use version;
use testapi;
use serial_terminal 'select_serial_terminal';
use utils qw(systemctl zypper_call);
use Mojo::Util 'trim';
use version_utils qw(is_rt);
use Utils::Architectures qw(is_s390x);

my $final_result = 'ok';
my $outfile = '/tmp/fips_packages_mismatch';
my $version = get_required_var("VERSION");

my %product_versions = (
    '15-SP4' => {
        kernel_ver => '5.14.21-150400.24.46.1',
        kernelRT_ver => '5.14.21-150400.15.11.1',
        openssl_ver => '1.1.1l-150400.7.28.1',
        gnutls_ver => '3.7.3-150400.4.35.1',
        gcrypt_ver => '1.9.4-150400.6.8.1',
        nss_ver => '3.79.4-150400.3.29.1',
        ica_ver => '4.2.1-150400.3.8.1',
        nettle_ver => '3.7.3-150400.2.21',
    },
    '15-SP6' => {
        kernel_ver => '6.4.0-150600.23.7.3',
        kernelRT_ver => '6.4.0-150600.13.5.2',
        openssl_ver => '3.0.8-150600.5.3.1',
        gnutls_ver => '3.8.0-150600.4.6.1',
        gcrypt_ver => '1.10.1-150600.3.3.1',
        nss_ver => '3.90.0-150600.3.3.1',
        ica_ver => '4.3.0-150600.3.3.1',
        nettle_ver => '3.9.1-150600.2.1.1',
    },
    '15-SP7' => {
        kernel_ver => '6.4.0-150600.23.7.3',
        kernelRT_ver => '6.4.0-150600.13.5.2',
        openssl_ver => '3.0.8-150600.5.3.1',
        gnutls_ver => '3.8.0-150600.4.6.1',
        gcrypt_ver => '1.10.1-150600.3.3.1',
        nss_ver => '3.90.0-150600.3.3.1',
        ica_ver => '4.3.0-150600.3.3.1',
        nettle_ver => '3.9.1-150600.2.1.1',
    }
);
#
# my $version = $product_versions{$version_get};

my %packages_common = (
    'kernel-default' => $version->{$kernel_ver},
    'kernel-default-devel' => $version->{$kernel_ver},
    'kernel-devel' => $version->{$kernel_ver},
    'kernel-source' => $version->{$kernel_ver},
    'kernel-default-devel-debuginfo' => $version->{$kernel_ver},
    'kernel-default-debuginfo' => $version->{$kernel_ver},
    'kernel-default-debugsource' => $version->{$kernel_ver},
    'libopenssl1_1' => $version->{$openssl_ver},
    'libopenssl1_1-hmac' => $version->{$openssl_ver},
    'libopenssl1_1-32bit' => $version->{$openssl_ver},
    'libopenssl1_1-hmac-32bit' => $version->{$openssl_ver},
    libgnutls30 => $version->{$gnutls_ver},
    'libgnutls30-hmac' => $version->{$gnutls_ver},
    'libgnutls-devel' => $version->{$gnutls_ver},
    libnettle8 => $version->{$nettle_ver},
    libgcrypt20 => $version->{$gcrypt_ver},
    'libgcrypt20-hmac' => $version->{$gcrypt_ver},
    'libgcrypt-devel' => $version->{$gcrypt_ver},
    'mozilla-nss-tools' => $version->{$nss_ver},
    'mozilla-nss-debugsource' => $version->{$nss_ver},
    'mozilla-nss' => $version->{$nss_ver},
    'mozilla-nss-certs' => $version->{$nss_ver},
    'mozilla-nss-devel' => $version->{$nss_ver},
    'mozilla-nss-debuginfo' => $version->{$nss_ver}
);

my %packages_s390x = (
    libica4 => $version->{$ica_ver},
    'libica-tools' => $version->{$ica_ver}
);

my %packages_rt = (
    'kernel-rt' => $version->{$kernelRT_ver},
    'kernel-devel-rt' => $version->{$kernelRT_ver},
    'kernel-source-rt' => $version->{$kernelRT_ver}
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

    foreach my $package (keys %packages_common) {
        eval {
            zypper_call('in --oldpackage ' . $package . '-' . $packages_common{$package});
        } or do {
            my $err = $@;
            record_info("$guest failure: $err");
        };
    }

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
