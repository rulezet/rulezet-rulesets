rule rule_LatLoader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LatLoader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LatLoader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LatLoader_offensive_tool_keyword = /\sLatLoader\.py/ nocase ascii wide
                        $string2_LatLoader_offensive_tool_keyword = /\/LatLoader\.git/ nocase ascii wide
                        $string3_LatLoader_offensive_tool_keyword = /\/LatLoader\.py/ nocase ascii wide
                        $string4_LatLoader_offensive_tool_keyword = /\[\+\]\sLooking\sfor\sthe\sSSN\svia\sHalos\sGate/ nocase ascii wide
                        $string5_LatLoader_offensive_tool_keyword = /\\LatLoader\.py/ nocase ascii wide
                        $string6_LatLoader_offensive_tool_keyword = /\\LatLoader\-main/ nocase ascii wide
                        $string7_LatLoader_offensive_tool_keyword = "27f70a1d533f7a3b8703d89904ae4541d96c8c656661872a495f592f9ed80d9e" nocase ascii wide
                        $string8_LatLoader_offensive_tool_keyword = "45787955618ba3211b89021ddf23ecc5d2b55397a006190455c4070dad964572" nocase ascii wide
                        $string9_LatLoader_offensive_tool_keyword = /cmd\.exe\s\/c\sC\:\\\\Windows\\\\DiskSnapShot\.exe\s\&\&\secho\s\-\-path\sC\:\\\\Windows\\\\CCMCache\\\\cache/ nocase ascii wide
                        $string10_LatLoader_offensive_tool_keyword = "f0f8f8de178f91de8fe054b6450fa0d2291ad7693035f2c52df800e9168fb22d" nocase ascii wide
                        $string11_LatLoader_offensive_tool_keyword = "icyguider/LatLoader" nocase ascii wide
                        $string12_LatLoader_offensive_tool_keyword = "OPERATORCHANGEMEPLZZZ" nocase ascii wide

    condition:
        any of them
}