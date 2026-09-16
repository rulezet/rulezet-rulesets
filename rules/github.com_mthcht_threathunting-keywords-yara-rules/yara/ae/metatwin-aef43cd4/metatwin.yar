rule metatwin
{
    meta:
        description = "Detection patterns for the tool 'metatwin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metatwin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-Source\sc\:\\windows\\.{0,1000}\.exe\s\-Target\s.{0,1000}\.exe\s\-Sign/ nocase ascii wide
                        $string2 = /\s\-Source\sc\:\\windows\\system32\\.{0,1000}\.dll\s\-Target\s.{0,1000}\.exe\s\-Sign/ nocase ascii wide
                        $string3 = /\/metatwin\.git/ nocase ascii wide
                        $string4 = /\\dist\\sigthief\.exe/ nocase ascii wide
                        $string5 = /\\sigthief\.exe/ nocase ascii wide
                        $string6 = "Invoke-MetaTwin" nocase ascii wide
                        $string7 = /metatwin\.ps1/ nocase ascii wide
                        $string8 = "metatwin-master" nocase ascii wide
                        $string9 = /sigthief\.exe\.manifest/ nocase ascii wide
                        $string10 = "SigThief-master" nocase ascii wide

    condition:
        any of them
}