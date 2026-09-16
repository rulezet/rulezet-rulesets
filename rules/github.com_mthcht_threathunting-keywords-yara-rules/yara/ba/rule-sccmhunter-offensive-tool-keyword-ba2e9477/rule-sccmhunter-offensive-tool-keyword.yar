rule rule_sccmhunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sccmhunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sccmhunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sccmhunter_offensive_tool_keyword = /\.sccmhunter/ nocase ascii wide
                        $string2_sccmhunter_offensive_tool_keyword = "/sccmhunter" nocase ascii wide
                        $string3_sccmhunter_offensive_tool_keyword = /cmpivot\.py/ nocase ascii wide
                        $string4_sccmhunter_offensive_tool_keyword = /sccmhunter\.db/ nocase ascii wide
                        $string5_sccmhunter_offensive_tool_keyword = /sccmhunter\.git/ nocase ascii wide
                        $string6_sccmhunter_offensive_tool_keyword = /sccmhunter\.py/ nocase ascii wide
                        $string7_sccmhunter_offensive_tool_keyword = /sccmwtf\.py/ nocase ascii wide

    condition:
        any of them
}