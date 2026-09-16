rule rule_ctfr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ctfr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ctfr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ctfr_offensive_tool_keyword = /\sctfr\.py/ nocase ascii wide
                        $string2_ctfr_offensive_tool_keyword = /\/ctfr\.py/ nocase ascii wide
                        $string3_ctfr_offensive_tool_keyword = /\\ctfr\.py/ nocase ascii wide

    condition:
        any of them
}