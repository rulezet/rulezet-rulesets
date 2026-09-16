rule rule_RunAsWinTcb_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RunAsWinTcb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RunAsWinTcb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RunAsWinTcb_offensive_tool_keyword = /\/dllexploit\.cpp/ nocase ascii wide
                        $string2_RunAsWinTcb_offensive_tool_keyword = /\/dllexploit\.exe/ nocase ascii wide
                        $string3_RunAsWinTcb_offensive_tool_keyword = /\/POC_DLL\.vcxproj/ nocase ascii wide
                        $string4_RunAsWinTcb_offensive_tool_keyword = /\/RunAsWinTcb\.git/ nocase ascii wide
                        $string5_RunAsWinTcb_offensive_tool_keyword = /\/RunAsWinTcb\.iml/ nocase ascii wide
                        $string6_RunAsWinTcb_offensive_tool_keyword = /\\dllexploit\.cpp/ nocase ascii wide
                        $string7_RunAsWinTcb_offensive_tool_keyword = /\\dllexploit\.exe/ nocase ascii wide
                        $string8_RunAsWinTcb_offensive_tool_keyword = /\\POC_DLL\.dll/ nocase ascii wide
                        $string9_RunAsWinTcb_offensive_tool_keyword = /\\POC_DLL\.vcxproj/ nocase ascii wide
                        $string10_RunAsWinTcb_offensive_tool_keyword = /\\RunAsWinTcb\\/ nocase ascii wide
                        $string11_RunAsWinTcb_offensive_tool_keyword = "33BF8AA2-18DE-4ED9-9613-A4118CBFC32A" nocase ascii wide
                        $string12_RunAsWinTcb_offensive_tool_keyword = "cb291da763f1ac7b8221be536e9d110a4c937c749da51b15151975c1b84f8b6d" nocase ascii wide
                        $string13_RunAsWinTcb_offensive_tool_keyword = /Choosing\sDLL\sto\shijack\./ nocase ascii wide
                        $string14_RunAsWinTcb_offensive_tool_keyword = /RunAsWinTcb\.exe/ nocase ascii wide
                        $string15_RunAsWinTcb_offensive_tool_keyword = "RunAsWinTcb-master" nocase ascii wide
                        $string16_RunAsWinTcb_offensive_tool_keyword = "tastypepperoni/RunAsWinTcb" nocase ascii wide

    condition:
        any of them
}