rule rule_mhydeath_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mhydeath' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mhydeath"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mhydeath_offensive_tool_keyword = /\/mhydeath\.git/ nocase ascii wide
                        $string2_mhydeath_offensive_tool_keyword = /\/mhydeath\.sln/ nocase ascii wide
                        $string3_mhydeath_offensive_tool_keyword = /\/mhydeath\/main\.cpp/ nocase ascii wide
                        $string4_mhydeath_offensive_tool_keyword = /\/process_killer\.cpp/ nocase ascii wide
                        $string5_mhydeath_offensive_tool_keyword = /\\mhydeath64/ nocase ascii wide
                        $string6_mhydeath_offensive_tool_keyword = /\\process_killer\.cpp/ nocase ascii wide
                        $string7_mhydeath_offensive_tool_keyword = "0D17A4B4-A7C4-49C0-99E3-B856F9F3B271" nocase ascii wide
                        $string8_mhydeath_offensive_tool_keyword = /mhydeath\.exe/ nocase ascii wide
                        $string9_mhydeath_offensive_tool_keyword = "mhydeath-master" nocase ascii wide
                        $string10_mhydeath_offensive_tool_keyword = /process_killer\.exe/ nocase ascii wide
                        $string11_mhydeath_offensive_tool_keyword = "zer0condition/mhydeath" nocase ascii wide

    condition:
        any of them
}