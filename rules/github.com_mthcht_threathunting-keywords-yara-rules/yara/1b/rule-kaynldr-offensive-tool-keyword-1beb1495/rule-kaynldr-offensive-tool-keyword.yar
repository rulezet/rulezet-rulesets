rule rule_KaynLdr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KaynLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KaynLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KaynLdr_offensive_tool_keyword = /\sKaynInject\.h/ nocase ascii wide
                        $string2_KaynLdr_offensive_tool_keyword = /\/KaynLdr\.git/ nocase ascii wide
                        $string3_KaynLdr_offensive_tool_keyword = /\[\-\]\sCouldn\'t\schange\smemory\sprotection\sfrom\sRW\sto\sRX/ nocase ascii wide
                        $string4_KaynLdr_offensive_tool_keyword = /\[\-\]\sCouldn\'t\scopy\sdll\sbuffer/ nocase ascii wide
                        $string5_KaynLdr_offensive_tool_keyword = /\[\-\]\sCouldn\'t\sfind\sKaynLoader/ nocase ascii wide
                        $string6_KaynLdr_offensive_tool_keyword = /\[\+\]\sInjected\sthe\s.{0,1000}\sDLL\sinto\sprocess\s/ nocase ascii wide
                        $string7_KaynLdr_offensive_tool_keyword = /\[\+\]\sSuccessful\sallocated\sremote\smemory\:\slpRemoteLibraryBuffer\:\[/ nocase ascii wide
                        $string8_KaynLdr_offensive_tool_keyword = /\[\+\]\sSuccessful\schange\sprotection\:\sRW\s\-\>\sRX/ nocase ascii wide
                        $string9_KaynLdr_offensive_tool_keyword = /\[\+\]\sSuccessful\scopied\sdll\sbuffer/ nocase ascii wide
                        $string10_KaynLdr_offensive_tool_keyword = /\[\+\]\sSuccessful\sinjected\sDLL\:\shThread\:/ nocase ascii wide
                        $string11_KaynLdr_offensive_tool_keyword = /\\KaynInject\.h/ nocase ascii wide
                        $string12_KaynLdr_offensive_tool_keyword = /\\KaynLdr\\KaynInject\\/ nocase ascii wide
                        $string13_KaynLdr_offensive_tool_keyword = /\\KaynLdr\-main\\/ nocase ascii wide
                        $string14_KaynLdr_offensive_tool_keyword = /\\src\\KaynInject\.c/ nocase ascii wide
                        $string15_KaynLdr_offensive_tool_keyword = /\\src\\KaynLdr\.c/ nocase ascii wide
                        $string16_KaynLdr_offensive_tool_keyword = "Call KaynLoader in a remote thread" nocase ascii wide
                        $string17_KaynLdr_offensive_tool_keyword = "Call KaynLoader in a remote thread" nocase ascii wide
                        $string18_KaynLdr_offensive_tool_keyword = "Cracked5pider/KaynLdr" nocase ascii wide
                        $string19_KaynLdr_offensive_tool_keyword = "Hello from KaynLdr" nocase ascii wide
                        $string20_KaynLdr_offensive_tool_keyword = /KaynInject\.x64\.exe/ nocase ascii wide
                        $string21_KaynLdr_offensive_tool_keyword = /KaynInject\.x86\.exe/ nocase ascii wide
                        $string22_KaynLdr_offensive_tool_keyword = "KAYNINJECT_KAYNINJECT_H" nocase ascii wide
                        $string23_KaynLdr_offensive_tool_keyword = /KaynLdr\.x64\.dll/ nocase ascii wide
                        $string24_KaynLdr_offensive_tool_keyword = "KAYNLDR_KAYNLDR_H" nocase ascii wide
                        $string25_KaynLdr_offensive_tool_keyword = "Write Dll buffer into remote memory" nocase ascii wide

    condition:
        any of them
}