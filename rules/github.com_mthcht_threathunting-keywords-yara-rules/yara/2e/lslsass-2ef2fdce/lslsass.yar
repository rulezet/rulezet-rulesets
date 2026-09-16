rule lslsass
{
    meta:
        description = "Detection patterns for the tool 'lslsass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lslsass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/lsass64\.exe/ nocase ascii wide
                        $string2 = /\\lsass64\.exe/ nocase ascii wide
                        $string3 = /\\lslsass\.exe/ nocase ascii wide
                        $string4 = "b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e" nocase ascii wide

    condition:
        any of them
}