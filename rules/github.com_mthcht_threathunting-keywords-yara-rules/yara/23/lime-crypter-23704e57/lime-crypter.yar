rule Lime_Crypter
{
    meta:
        description = "Detection patterns for the tool 'Lime-Crypter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lime-Crypter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Lime\-Crypter\.git/ nocase ascii wide
                        $string2 = /\\Lime\-Crypter\.sln/ nocase ascii wide
                        $string3 = /\\Lime\-Crypter\\/ nocase ascii wide
                        $string4 = "F93C99ED-28C9-48C5-BB90-DD98F18285A6" nocase ascii wide
                        $string5 = /Lime\-Crypter\.exe/ nocase ascii wide
                        $string6 = "NYAN-x-CAT/Lime-Crypter" nocase ascii wide
                        $string7 = /Release\.Lime\-Crypter\.v0\.5\.1\.exe\.zip/ nocase ascii wide

    condition:
        any of them
}