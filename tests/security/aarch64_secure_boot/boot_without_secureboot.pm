# Copyright 2021 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: For aarch64 system with secureboot enabled,
#          we need make sure it can boot up successfully
#          after disabling the secureboot
#
# Maintainer: QE Security <none@suse.de>
# Tags: poo#81712

use Mojo::Base 'opensusebasetest';
use testapi;
use serial_terminal 'select_serial_terminal';
use utils;
use power_action_utils 'power_action';
use security::secureboot 'handle_secureboot';

sub run {
    my $self = shift;
    select_serial_terminal;

    # Reboot and disable secureboot via tianocore_enter_menu (F2 hammering),
    # which is more reliable than the GRUB-console 'exit' trick on aarch64
    power_action('reboot', textmode => 1);
    handle_secureboot($self, 'disable');

    # Make sure secureboot is disabled
    select_serial_terminal;
    validate_script_output('mokutil --sb-state', sub { m/SecureBoot disabled/ });
}

1;
