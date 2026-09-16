rule nullinux
{
    meta:
        description = "Detection patterns for the tool 'nullinux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nullinux"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\snullinux\.py/
                        $string2 = /\/nullinux\.git/
                        $string3 = /\/nullinux\.py/
                        $string4 = /\/nullinux_users\.txt/
                        $string5 = "/usr/local/bin/nullinux"
                        $string6 = /\]\sStarting\snullinux\ssetup\sscript/
                        $string7 = "e4df5a904c8eb505cb63d9905c398f632cf97ba193a6e25569d561d44f69e623"
                        $string8 = /enum_enumdomusers\(/
                        $string9 = "m8sec/nullinux"
                        $string10 = "nullinux -rid -range "
                        $string11 = "nullinux -shares -U "
                        $string12 = "nullinux -users "

    condition:
        any of them
}