rule rule_lsa_whisperer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lsa-whisperer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsa-whisperer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_lsa_whisperer_greyware_tool_keyword = /\/lsa\-whisperer\-.{0,1000}\.zip/ nocase ascii wide
                        $string2_lsa_whisperer_greyware_tool_keyword = /\/lsa\-whisperer\.git/ nocase ascii wide
                        $string3_lsa_whisperer_greyware_tool_keyword = /\\lsa\-whisperer\-/ nocase ascii wide
                        $string4_lsa_whisperer_greyware_tool_keyword = "EvanMcBroom/lsa-whisperer" nocase ascii wide

    condition:
        any of them
}