rule sudoers
{
    meta:
        description = "Detection patterns for the tool 'sudoers' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudoers"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /echo\s.{0,1000}\sALL\=\(ALL\)\sNOPASSWD\:\sALL.{0,1000}\s\>\>\/etc\/sudoers/
                        $string2 = /echo\s.{0,1000}\sALL\=NOPASSWD\:\s\/bin\/bash.{0,1000}\s\>\>\/etc\/sudoers/

    condition:
        any of them
}