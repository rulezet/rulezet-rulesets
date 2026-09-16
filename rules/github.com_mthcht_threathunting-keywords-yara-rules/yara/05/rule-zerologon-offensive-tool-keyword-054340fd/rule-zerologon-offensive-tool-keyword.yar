rule rule_zerologon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'zerologon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zerologon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_zerologon_offensive_tool_keyword = /\.py\s\-no\-pass\s\-just\-dc\s/ nocase ascii wide
                        $string2_zerologon_offensive_tool_keyword = /\/nrpc\.py/ nocase ascii wide
                        $string3_zerologon_offensive_tool_keyword = /\\zero\.exe\s.{0,1000}ProgramData/ nocase ascii wide
                        $string4_zerologon_offensive_tool_keyword = /cve\-2020\-1472\-exploit\.py/ nocase ascii wide

    condition:
        any of them
}