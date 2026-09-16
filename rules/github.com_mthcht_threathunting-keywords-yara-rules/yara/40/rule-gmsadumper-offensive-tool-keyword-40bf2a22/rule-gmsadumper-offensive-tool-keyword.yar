rule rule_gMSADumper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gMSADumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gMSADumper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gMSADumper_offensive_tool_keyword = "/gMSADumper" nocase ascii wide
                        $string2_gMSADumper_offensive_tool_keyword = /gMSADumper\.py/ nocase ascii wide
                        $string3_gMSADumper_offensive_tool_keyword = "micahvandeusen/gMSADumper" nocase ascii wide

    condition:
        any of them
}