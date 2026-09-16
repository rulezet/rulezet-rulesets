rule rule_DarkWidow_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DarkWidow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DarkWidow"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DarkWidow_offensive_tool_keyword = /\s\<PPID\sto\sspoof\>\\n\\n/ nocase ascii wide
                        $string2_DarkWidow_offensive_tool_keyword = /\sblindeventlog\.exe/ nocase ascii wide
                        $string3_DarkWidow_offensive_tool_keyword = /\/blindeventlog\.exe/ nocase ascii wide
                        $string4_DarkWidow_offensive_tool_keyword = /\/DarkWidow\.git/ nocase ascii wide
                        $string5_DarkWidow_offensive_tool_keyword = /\[\!\]\sFailed\sto\sKill\sEventLog\sService/ nocase ascii wide
                        $string6_DarkWidow_offensive_tool_keyword = /\[\+\]\sEvent\sLogger\sis\sEither\sNOT\srunning\sor\sAlready\sKilled\sPreviously\!/ nocase ascii wide
                        $string7_DarkWidow_offensive_tool_keyword = /\[\+\]\sReady\sfor\sPost\-Exp\s\:\)/ nocase ascii wide
                        $string8_DarkWidow_offensive_tool_keyword = /\\blindeventlog\.exe/ nocase ascii wide
                        $string9_DarkWidow_offensive_tool_keyword = /\\DarkWidow\\src\\/ nocase ascii wide
                        $string10_DarkWidow_offensive_tool_keyword = /\\Running_msf_revshell/ nocase ascii wide
                        $string11_DarkWidow_offensive_tool_keyword = /\\x64\\Release\\indirect\.exe\s/ nocase ascii wide
                        $string12_DarkWidow_offensive_tool_keyword = /\]\sKilling\sEventLog\sThreads\s\(if\srunning\)/ nocase ascii wide
                        $string13_DarkWidow_offensive_tool_keyword = /\]\sShellcode\sDecryption\sStarted/ nocase ascii wide
                        $string14_DarkWidow_offensive_tool_keyword = "=========== Havoc and msf revshell ========" nocase ascii wide
                        $string15_DarkWidow_offensive_tool_keyword = "4D1B765D-1287-45B1-AEDC-C4B96CF5CAA2" nocase ascii wide
                        $string16_DarkWidow_offensive_tool_keyword = "6C9CF6A0-C098-4341-8DD1-2FCBA9594067" nocase ascii wide
                        $string17_DarkWidow_offensive_tool_keyword = "DarkWidow-main" nocase ascii wide
                        $string18_DarkWidow_offensive_tool_keyword = "reveng007/DarkWidow" nocase ascii wide

    condition:
        any of them
}