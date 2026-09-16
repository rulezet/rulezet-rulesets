rule PstPassword
{
    meta:
        description = "Detection patterns for the tool 'PstPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PstPassword"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /PstPassword\.exe/ nocase ascii wide
                        $string2 = /pstpassword\.zip/ nocase ascii wide
                        $string3 = /pstpassword_setup\.exe/ nocase ascii wide

    condition:
        any of them
}