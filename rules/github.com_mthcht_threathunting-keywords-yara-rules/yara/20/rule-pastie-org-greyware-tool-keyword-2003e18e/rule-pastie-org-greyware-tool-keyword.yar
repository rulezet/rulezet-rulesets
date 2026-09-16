rule rule_pastie_org_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pastie.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastie.org"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pastie_org_greyware_tool_keyword = /http\:\/\/pastie\.org\/p\/.{0,1000}\/raw/ nocase ascii wide
                        $string2_pastie_org_greyware_tool_keyword = /http\:\/\/pastie\.org\/pastes\/create/ nocase ascii wide

    condition:
        any of them
}