rule rule_lslsass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lslsass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lslsass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lslsass_offensive_tool_keyword = /\/lsass64\.exe/ nocase ascii wide
                        $string2_lslsass_offensive_tool_keyword = /\\lsass64\.exe/ nocase ascii wide
                        $string3_lslsass_offensive_tool_keyword = /\\lslsass\.exe/ nocase ascii wide
                        $string4_lslsass_offensive_tool_keyword = "b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e" nocase ascii wide

    condition:
        any of them
}