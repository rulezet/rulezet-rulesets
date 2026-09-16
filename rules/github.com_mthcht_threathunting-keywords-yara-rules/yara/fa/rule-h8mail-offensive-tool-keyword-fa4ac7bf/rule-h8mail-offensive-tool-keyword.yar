rule rule_h8mail_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'h8mail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "h8mail"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_h8mail_offensive_tool_keyword = "/h8mail/" nocase ascii wide
                        $string2_h8mail_offensive_tool_keyword = "h8mail -" nocase ascii wide
                        $string3_h8mail_offensive_tool_keyword = "h8mail" nocase ascii wide
                        $string4_h8mail_offensive_tool_keyword = "install h8mail" nocase ascii wide
                        $string5_h8mail_offensive_tool_keyword = "khast3x/h8mail" nocase ascii wide
                        $string6_h8mail_offensive_tool_keyword = "opencubicles/h8mail" nocase ascii wide

    condition:
        any of them
}