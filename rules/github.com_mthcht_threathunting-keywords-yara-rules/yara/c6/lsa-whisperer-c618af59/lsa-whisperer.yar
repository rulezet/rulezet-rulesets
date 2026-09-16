rule lsa_whisperer
{
    meta:
        description = "Detection patterns for the tool 'lsa-whisperer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsa-whisperer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/lsa\-whisperer\-.{0,1000}\.zip/ nocase ascii wide
                        $string2 = /\/lsa\-whisperer\.git/ nocase ascii wide
                        $string3 = /\\lsa\-whisperer\-/ nocase ascii wide
                        $string4 = "EvanMcBroom/lsa-whisperer" nocase ascii wide

    condition:
        any of them
}