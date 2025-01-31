from testapi import *

def run(self):
    print(self)
    assert_screen('openqa-logged-in')
    assert_and_click('openqa-search')
    type_string('shutdown.pm')
    send_key('ret')
    assert_screen('openqa-search-results')

    # import further Perl-based libraries (besides `testapi`)
    perl.require('x11utils')

    # use imported Perl-based libraries; call Perl function that would be called via "named arguments" in Perl
    # note: In Perl the call would have been: x11_start_program('flatpak run com.obsproject.Studio', target_match => 'obsproject-wizard')
    #
    # See the explanation in the "Notes on the Python API" section.
    perl.x11utils.x11_start_program('flatpak run com.obsproject.Studio', 'target_match', 'obsproject-wizard')

def switch_to_root_console():
    send_key('ctrl-alt-f3')

def post_fail_hook(self):
    switch_to_root_console()
    assert_script_run('openqa-cli api experimental/search q=shutdown.pm')

def test_flags(self):
    return {'fatal': 1}
