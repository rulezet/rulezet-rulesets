rule rule_esentutl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'esentutl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "esentutl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_esentutl_greyware_tool_keyword = /Esentutl.{0,1000}\/p\s\/o\s.{0,1000}\.dit/ nocase ascii wide
                        $string2_esentutl_greyware_tool_keyword = /esentutl\.exe\s\/y\s\/vss\s.{0,1000}\:\\windows\\ntds\\ntds\.dit/ nocase ascii wide

    condition:
        any of them
}