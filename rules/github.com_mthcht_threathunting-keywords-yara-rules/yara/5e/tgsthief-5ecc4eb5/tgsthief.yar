rule TGSThief
{
    meta:
        description = "Detection patterns for the tool 'TGSThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TGSThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/releases\/download\/.{0,1000}\/abc\.exe/ nocase ascii wide
                        $string2 = /\/TGSThief\.git/ nocase ascii wide
                        $string3 = "/TGSThief/" nocase ascii wide
                        $string4 = /\\TGSThief\\/ nocase ascii wide
                        $string5 = "MzHmO/TGSThief" nocase ascii wide
                        $string6 = "TGSThief-main" nocase ascii wide

    condition:
        any of them
}