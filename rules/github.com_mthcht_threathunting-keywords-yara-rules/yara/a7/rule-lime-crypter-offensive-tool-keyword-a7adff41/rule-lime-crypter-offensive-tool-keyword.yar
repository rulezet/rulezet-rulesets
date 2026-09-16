rule rule_Lime_Crypter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lime-Crypter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lime-Crypter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Lime_Crypter_offensive_tool_keyword = /\/Lime\-Crypter\.git/ nocase ascii wide
                        $string2_Lime_Crypter_offensive_tool_keyword = /\\Lime\-Crypter\.sln/ nocase ascii wide
                        $string3_Lime_Crypter_offensive_tool_keyword = /\\Lime\-Crypter\\/ nocase ascii wide
                        $string4_Lime_Crypter_offensive_tool_keyword = "F93C99ED-28C9-48C5-BB90-DD98F18285A6" nocase ascii wide
                        $string5_Lime_Crypter_offensive_tool_keyword = /Lime\-Crypter\.exe/ nocase ascii wide
                        $string6_Lime_Crypter_offensive_tool_keyword = "NYAN-x-CAT/Lime-Crypter" nocase ascii wide
                        $string7_Lime_Crypter_offensive_tool_keyword = /Release\.Lime\-Crypter\.v0\.5\.1\.exe\.zip/ nocase ascii wide

    condition:
        any of them
}