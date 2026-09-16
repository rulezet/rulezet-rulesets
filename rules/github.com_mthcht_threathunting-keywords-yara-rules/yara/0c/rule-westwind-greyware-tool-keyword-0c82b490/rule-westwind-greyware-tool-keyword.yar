rule rule_westwind_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'westwind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "westwind"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_westwind_greyware_tool_keyword = "gbfgfbopcfokdpkdigfmoeaajfmpkbnh" nocase ascii wide

    condition:
        any of them
}