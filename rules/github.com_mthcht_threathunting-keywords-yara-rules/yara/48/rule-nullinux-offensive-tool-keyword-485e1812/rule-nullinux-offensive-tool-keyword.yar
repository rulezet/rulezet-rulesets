rule rule_nullinux_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nullinux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nullinux"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nullinux_offensive_tool_keyword = /\snullinux\.py/
                        $string2_nullinux_offensive_tool_keyword = /\/nullinux\.git/
                        $string3_nullinux_offensive_tool_keyword = /\/nullinux\.py/
                        $string4_nullinux_offensive_tool_keyword = /\/nullinux_users\.txt/
                        $string5_nullinux_offensive_tool_keyword = "/usr/local/bin/nullinux"
                        $string6_nullinux_offensive_tool_keyword = /\]\sStarting\snullinux\ssetup\sscript/
                        $string7_nullinux_offensive_tool_keyword = "e4df5a904c8eb505cb63d9905c398f632cf97ba193a6e25569d561d44f69e623"
                        $string8_nullinux_offensive_tool_keyword = /enum_enumdomusers\(/
                        $string9_nullinux_offensive_tool_keyword = "m8sec/nullinux"
                        $string10_nullinux_offensive_tool_keyword = "nullinux -rid -range "
                        $string11_nullinux_offensive_tool_keyword = "nullinux -shares -U "
                        $string12_nullinux_offensive_tool_keyword = "nullinux -users "

    condition:
        any of them
}