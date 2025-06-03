# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Unlocking LUKS volumes with TPM2
#
# Maintainer: QE Security <none@suse.de>
# Tags: poo#107488, tc#1769799, poo#112241

use strict;
use warnings;
use base qw(consoletest opensusebasetest);
use testapi;
use utils qw(quit_packagekit zypper_call);
use Utils::Backends 'is_pvm';
use power_action_utils 'power_action';
use version_utils 'is_sle';

sub run {
    my $self = shift;
    my $enter_passphrase_for_root = $testapi::distri->get_enter_passphrase_for_root();
    my $enter_passphrase_for_swap = $testapi::distri->get_enter_passphrase_for_swap();
    my $grub_menu = $testapi::distri->get_grub_menu_installed_system();

    select_console 'root-console';
    quit_packagekit;
    zypper_call('in expect');
    zypper_call('in -t pattern gnome');

    # Get all LUKS partitions
    my @luks_parts = split(/\n/, script_output q(blkid | grep crypto_LUKS | awk -F: '{print $1}'));
    record_info('LUKS partitions', "Found LUKS partitions: " . join(', ', @luks_parts));

    # Get all LUKS volumes from crypttab
    my @luks_volumes = split(/\n/, script_output q(awk '{print $1}' /etc/crypttab | grep -v '^#' | grep -v '^$'));
    record_info('LUKS volumes', "Found LUKS volumes: " . join(', ', @luks_volumes));

    # Verify all volumes are LUKS2
    for my $volume (@luks_volumes) {
        validate_script_output("cryptsetup status $volume", sub { m/LUKS2/ });
        record_info('LUKS2 verified', "Volume $volume is LUKS2");
    }
    # Find the entry for the LUKS2 volume in /etc/crypttab (it may appear referenced by its UUID) and add the tpm2-device= option
    assert_script_run q(sed -i 's/x-initrd.attach/x-initrd.attach,tpm2-device=auto/g' /etc/crypttab);

    # Regenerate the initrd.
    assert_script_run('dracut -f');
    set_var('DESKTOP', 'GNOME');

    # reboot to make new initrd effective
    power_action('reboot', textmode => 1, keepconsole => is_pvm());
    reconnect_mgmt_console() if is_pvm();

    $enter_passphrase_for_root->expect_is_shown();
    $enter_passphrase_for_root->enter();

    $grub_menu->expect_is_shown();
    $grub_menu->select_first_entry();

    $enter_passphrase_for_swap->expect_is_shown();
    $enter_passphrase_for_swap->enter();

    set_var('DESKTOP', 'GNOME');
    select_console 'root-console';

    # Enroll the LUKS2 volumes with TPM device
    for my $part (@luks_parts) {
        record_info('TPM2 enrollment', "Enrolling $part with TPM2");
        assert_script_run(
            "expect -c 'spawn systemd-cryptenroll --tpm2-device=auto $part; expect \"current passphrase*\"; send \"$testapi::password\\n\"; interact'"
        );
    }

    # Set ENCRYPT=0 now, since we don't need unlock the disk via password
    set_var('ENCRYPT', 0);
}

1;
