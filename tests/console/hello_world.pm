use base 'consoletest';
use strict;
use testapi;
sub run {
    select_console 'root-console';
    assert_script_run("echo 'Hello World!'");
}
1;
