rule RunAsWinTcb
{
    meta:
        description = "Detection patterns for the tool 'RunAsWinTcb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RunAsWinTcb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/dllexploit\.cpp/ nocase ascii wide
                        $string2 = /\/dllexploit\.exe/ nocase ascii wide
                        $string3 = /\/POC_DLL\.vcxproj/ nocase ascii wide
                        $string4 = /\/RunAsWinTcb\.git/ nocase ascii wide
                        $string5 = /\/RunAsWinTcb\.iml/ nocase ascii wide
                        $string6 = /\\dllexploit\.cpp/ nocase ascii wide
                        $string7 = /\\dllexploit\.exe/ nocase ascii wide
                        $string8 = /\\POC_DLL\.dll/ nocase ascii wide
                        $string9 = /\\POC_DLL\.vcxproj/ nocase ascii wide
                        $string10 = /\\RunAsWinTcb\\/ nocase ascii wide
                        $string11 = "33BF8AA2-18DE-4ED9-9613-A4118CBFC32A" nocase ascii wide
                        $string12 = "cb291da763f1ac7b8221be536e9d110a4c937c749da51b15151975c1b84f8b6d" nocase ascii wide
                        $string13 = /Choosing\sDLL\sto\shijack\./ nocase ascii wide
                        $string14 = /RunAsWinTcb\.exe/ nocase ascii wide
                        $string15 = "RunAsWinTcb-master" nocase ascii wide
                        $string16 = "tastypepperoni/RunAsWinTcb" nocase ascii wide

    condition:
        any of them
}