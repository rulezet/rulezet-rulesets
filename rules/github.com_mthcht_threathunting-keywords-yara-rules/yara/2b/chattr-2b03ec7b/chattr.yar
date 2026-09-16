rule chattr
{
    meta:
        description = "Detection patterns for the tool 'chattr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chattr"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /chattr\s\+i\s\$HISTFILE/ nocase ascii wide
                        $string2 = /chattr\s\+i\s.{0,1000}\.bash_history/
                        $string3 = /chattr\s\-ia\s.{0,1000}\/etc\/passwd/
                        $string4 = /chattr\s\-ia\s.{0,1000}\/etc\/shadow/
                        $string5 = /chattr\s\-ia\s.{0,1000}\/etc\/sudoers/

    condition:
        any of them
}