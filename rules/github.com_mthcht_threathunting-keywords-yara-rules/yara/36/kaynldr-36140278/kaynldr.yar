rule KaynLdr
{
    meta:
        description = "Detection patterns for the tool 'KaynLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KaynLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sKaynInject\.h/ nocase ascii wide
                        $string2 = /\/KaynLdr\.git/ nocase ascii wide
                        $string3 = /\[\-\]\sCouldn\'t\schange\smemory\sprotection\sfrom\sRW\sto\sRX/ nocase ascii wide
                        $string4 = /\[\-\]\sCouldn\'t\scopy\sdll\sbuffer/ nocase ascii wide
                        $string5 = /\[\-\]\sCouldn\'t\sfind\sKaynLoader/ nocase ascii wide
                        $string6 = /\[\+\]\sInjected\sthe\s.{0,1000}\sDLL\sinto\sprocess\s/ nocase ascii wide
                        $string7 = /\[\+\]\sSuccessful\sallocated\sremote\smemory\:\slpRemoteLibraryBuffer\:\[/ nocase ascii wide
                        $string8 = /\[\+\]\sSuccessful\schange\sprotection\:\sRW\s\-\>\sRX/ nocase ascii wide
                        $string9 = /\[\+\]\sSuccessful\scopied\sdll\sbuffer/ nocase ascii wide
                        $string10 = /\[\+\]\sSuccessful\sinjected\sDLL\:\shThread\:/ nocase ascii wide
                        $string11 = /\\KaynInject\.h/ nocase ascii wide
                        $string12 = /\\KaynLdr\\KaynInject\\/ nocase ascii wide
                        $string13 = /\\KaynLdr\-main\\/ nocase ascii wide
                        $string14 = /\\src\\KaynInject\.c/ nocase ascii wide
                        $string15 = /\\src\\KaynLdr\.c/ nocase ascii wide
                        $string16 = "Call KaynLoader in a remote thread" nocase ascii wide
                        $string17 = "Call KaynLoader in a remote thread" nocase ascii wide
                        $string18 = "Cracked5pider/KaynLdr" nocase ascii wide
                        $string19 = "Hello from KaynLdr" nocase ascii wide
                        $string20 = /KaynInject\.x64\.exe/ nocase ascii wide
                        $string21 = /KaynInject\.x86\.exe/ nocase ascii wide
                        $string22 = "KAYNINJECT_KAYNINJECT_H" nocase ascii wide
                        $string23 = /KaynLdr\.x64\.dll/ nocase ascii wide
                        $string24 = "KAYNLDR_KAYNLDR_H" nocase ascii wide
                        $string25 = "Write Dll buffer into remote memory" nocase ascii wide

    condition:
        any of them
}