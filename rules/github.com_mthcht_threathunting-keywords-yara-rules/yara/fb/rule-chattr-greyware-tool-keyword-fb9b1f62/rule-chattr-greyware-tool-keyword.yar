rule rule_chattr_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chattr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chattr"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_chattr_greyware_tool_keyword = /chattr\s\+i\s\$HISTFILE/ nocase ascii wide
                        $string2_chattr_greyware_tool_keyword = /chattr\s\+i\s.{0,1000}\.bash_history/
                        $string3_chattr_greyware_tool_keyword = /chattr\s\-ia\s.{0,1000}\/etc\/passwd/
                        $string4_chattr_greyware_tool_keyword = /chattr\s\-ia\s.{0,1000}\/etc\/shadow/
                        $string5_chattr_greyware_tool_keyword = /chattr\s\-ia\s.{0,1000}\/etc\/sudoers/

    condition:
        any of them
}