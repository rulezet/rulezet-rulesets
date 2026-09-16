rule DarkWidow
{
    meta:
        description = "Detection patterns for the tool 'DarkWidow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DarkWidow"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\<PPID\sto\sspoof\>\\n\\n/ nocase ascii wide
                        $string2 = /\sblindeventlog\.exe/ nocase ascii wide
                        $string3 = /\/blindeventlog\.exe/ nocase ascii wide
                        $string4 = /\/DarkWidow\.git/ nocase ascii wide
                        $string5 = /\[\!\]\sFailed\sto\sKill\sEventLog\sService/ nocase ascii wide
                        $string6 = /\[\+\]\sEvent\sLogger\sis\sEither\sNOT\srunning\sor\sAlready\sKilled\sPreviously\!/ nocase ascii wide
                        $string7 = /\[\+\]\sReady\sfor\sPost\-Exp\s\:\)/ nocase ascii wide
                        $string8 = /\\blindeventlog\.exe/ nocase ascii wide
                        $string9 = /\\DarkWidow\\src\\/ nocase ascii wide
                        $string10 = /\\Running_msf_revshell/ nocase ascii wide
                        $string11 = /\\x64\\Release\\indirect\.exe\s/ nocase ascii wide
                        $string12 = /\]\sKilling\sEventLog\sThreads\s\(if\srunning\)/ nocase ascii wide
                        $string13 = /\]\sShellcode\sDecryption\sStarted/ nocase ascii wide
                        $string14 = "=========== Havoc and msf revshell ========" nocase ascii wide
                        $string15 = "4D1B765D-1287-45B1-AEDC-C4B96CF5CAA2" nocase ascii wide
                        $string16 = "6C9CF6A0-C098-4341-8DD1-2FCBA9594067" nocase ascii wide
                        $string17 = "DarkWidow-main" nocase ascii wide
                        $string18 = "reveng007/DarkWidow" nocase ascii wide

    condition:
        any of them
}