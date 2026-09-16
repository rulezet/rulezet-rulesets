rule rule_sudoers_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sudoers' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudoers"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sudoers_greyware_tool_keyword = /echo\s.{0,1000}\sALL\=\(ALL\)\sNOPASSWD\:\sALL.{0,1000}\s\>\>\/etc\/sudoers/
                        $string2_sudoers_greyware_tool_keyword = /echo\s.{0,1000}\sALL\=NOPASSWD\:\s\/bin\/bash.{0,1000}\s\>\>\/etc\/sudoers/

    condition:
        any of them
}