rule rule_Gotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Gotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Gotato_offensive_tool_keyword = " -p 4644 -n mal" nocase ascii wide
                        $string2_Gotato_offensive_tool_keyword = " Process spawned with stolen token!" nocase ascii wide
                        $string3_Gotato_offensive_tool_keyword = /\/Gotato\.git/ nocase ascii wide
                        $string4_Gotato_offensive_tool_keyword = /\/gotato\.go/ nocase ascii wide
                        $string5_Gotato_offensive_tool_keyword = /\[\+\]\sStole\stoken\sfrom/ nocase ascii wide
                        $string6_Gotato_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\mal/ nocase ascii wide
                        $string7_Gotato_offensive_tool_keyword = "gotato -m http" nocase ascii wide
                        $string8_Gotato_offensive_tool_keyword = "gotato -m pipe" nocase ascii wide
                        $string9_Gotato_offensive_tool_keyword = /gotato.{0,1000}\s\-n\smal/ nocase ascii wide
                        $string10_Gotato_offensive_tool_keyword = /gotato.{0,1000}\s\-p\s4644/ nocase ascii wide
                        $string11_Gotato_offensive_tool_keyword = /Gotato\-main\./ nocase ascii wide
                        $string12_Gotato_offensive_tool_keyword = /httpntlm\.go/ nocase ascii wide
                        $string13_Gotato_offensive_tool_keyword = /httpntlm\.old/ nocase ascii wide
                        $string14_Gotato_offensive_tool_keyword = "iammaguire/Gotato" nocase ascii wide
                        $string15_Gotato_offensive_tool_keyword = "TlRMTVNTUAACAAAABgAGADgAAAAFAomih5Y9EpIdLmMAAAAAAAAAAIAAgAA" nocase ascii wide

    condition:
        any of them
}