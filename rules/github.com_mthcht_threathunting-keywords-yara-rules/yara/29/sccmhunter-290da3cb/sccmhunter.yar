rule sccmhunter
{
    meta:
        description = "Detection patterns for the tool 'sccmhunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sccmhunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.sccmhunter/ nocase ascii wide
                        $string2 = "/sccmhunter" nocase ascii wide
                        $string3 = /cmpivot\.py/ nocase ascii wide
                        $string4 = /sccmhunter\.db/ nocase ascii wide
                        $string5 = /sccmhunter\.git/ nocase ascii wide
                        $string6 = /sccmhunter\.py/ nocase ascii wide
                        $string7 = /sccmwtf\.py/ nocase ascii wide

    condition:
        any of them
}