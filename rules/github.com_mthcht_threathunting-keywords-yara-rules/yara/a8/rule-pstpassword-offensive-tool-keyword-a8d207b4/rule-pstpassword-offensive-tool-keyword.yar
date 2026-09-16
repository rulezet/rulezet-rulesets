rule rule_PstPassword_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PstPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PstPassword"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PstPassword_offensive_tool_keyword = /PstPassword\.exe/ nocase ascii wide
                        $string2_PstPassword_offensive_tool_keyword = /pstpassword\.zip/ nocase ascii wide
                        $string3_PstPassword_offensive_tool_keyword = /pstpassword_setup\.exe/ nocase ascii wide

    condition:
        any of them
}