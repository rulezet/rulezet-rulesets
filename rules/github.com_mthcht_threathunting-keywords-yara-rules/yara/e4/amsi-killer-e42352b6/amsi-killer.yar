rule Amsi_Killer
{
    meta:
        description = "Detection patterns for the tool 'Amsi-Killer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amsi-Killer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Amsi\-Killer\.git/ nocase ascii wide
                        $string2 = "AMSI patched in all powershells" nocase ascii wide
                        $string3 = /Amsi\-Killer\.exe/ nocase ascii wide
                        $string4 = /Amsi\-Killer\.sln/ nocase ascii wide
                        $string5 = /Amsi\-Killer\.vcxproj/ nocase ascii wide
                        $string6 = "Amsi-Killer-master" nocase ascii wide
                        $string7 = "E2E64E89-8ACE-4AA1-9340-8E987F5F142F" nocase ascii wide
                        $string8 = "ZeroMemoryEx/Amsi-Killer" nocase ascii wide

    condition:
        any of them
}