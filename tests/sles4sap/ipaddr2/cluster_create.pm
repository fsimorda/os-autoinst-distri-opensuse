# Copyright SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later

# Summary: Create cluster
# Maintainer: QE-SAP <qe-sap@suse.de>, Michele Pagot <michele.pagot@suse.com>

use strict;
use warnings;
use Mojo::Base 'publiccloud::basetest';
use testapi;
use serial_terminal qw( select_serial_terminal );
use sles4sap::ipaddr2 qw(
  ipaddr2_bastion_pubip
  ipaddr2_cluster_create
  ipaddr2_deployment_logs
  ipaddr2_infra_destroy
  ipaddr2_cloudinit_logs
  ipaddr2_clean_network_peering
);

sub run {
    my ($self) = @_;

    die('Azure is the only CSP supported for the moment')
      unless check_var('PUBLIC_CLOUD_PROVIDER', 'AZURE');

    select_serial_terminal;

    my $bastion_ip = ipaddr2_bastion_pubip();

    record_info("TEST STAGE", "Init and configure the Pacemaker cluster");
    ipaddr2_cluster_create(bastion_ip => $bastion_ip, rootless => get_var('IPADDR2_ROOTLESS', '0'));
}

sub test_flags {
    return {fatal => 1, publiccloud_multi_module => 1};
}

sub post_fail_hook {
    my ($self) = shift;
    ipaddr2_deployment_logs() if check_var('IPADDR2_DIAGNOSTIC', 1);
    ipaddr2_cloudinit_logs() unless check_var('IPADDR2_CLOUDINIT', 0);
    if (my $ibsm_rg = get_var('IBSM_RG')) {
        ipaddr2_clean_network_peering(ibsm_rg => $ibsm_rg);
    }
    ipaddr2_infra_destroy();
    $self->SUPER::post_fail_hook;
}

1;