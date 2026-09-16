rule rule_metatwin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'metatwin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metatwin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_metatwin_offensive_tool_keyword = /\s\-Source\sc\:\\windows\\.{0,1000}\.exe\s\-Target\s.{0,1000}\.exe\s\-Sign/ nocase ascii wide
                        $string2_metatwin_offensive_tool_keyword = /\s\-Source\sc\:\\windows\\system32\\.{0,1000}\.dll\s\-Target\s.{0,1000}\.exe\s\-Sign/ nocase ascii wide
                        $string3_metatwin_offensive_tool_keyword = /\/metatwin\.git/ nocase ascii wide
                        $string4_metatwin_offensive_tool_keyword = /\\dist\\sigthief\.exe/ nocase ascii wide
                        $string5_metatwin_offensive_tool_keyword = /\\sigthief\.exe/ nocase ascii wide
                        $string6_metatwin_offensive_tool_keyword = "Invoke-MetaTwin" nocase ascii wide
                        $string7_metatwin_offensive_tool_keyword = /metatwin\.ps1/ nocase ascii wide
                        $string8_metatwin_offensive_tool_keyword = "metatwin-master" nocase ascii wide
                        $string9_metatwin_offensive_tool_keyword = /sigthief\.exe\.manifest/ nocase ascii wide
                        $string10_metatwin_offensive_tool_keyword = "SigThief-master" nocase ascii wide

    condition:
        any of them
}