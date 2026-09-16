rule PoolParty
{
    meta:
        description = "Detection patterns for the tool 'PoolParty' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoolParty"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPoolParty\.cpp/ nocase ascii wide
                        $string2 = /\sPoolParty\.exe/ nocase ascii wide
                        $string3 = /\/HandleHijacker\.cpp/ nocase ascii wide
                        $string4 = /\/HandleHijacker\.hpp/ nocase ascii wide
                        $string5 = /\/PoolParty\.cpp/ nocase ascii wide
                        $string6 = /\/PoolParty\.exe/ nocase ascii wide
                        $string7 = /\/PoolParty\.git/ nocase ascii wide
                        $string8 = /\/PoolParty\.hpp/ nocase ascii wide
                        $string9 = /\/PoolParty\.sln/ nocase ascii wide
                        $string10 = /\/PoolParty\.vcxproj/ nocase ascii wide
                        $string11 = /\\HandleHijacker\.cpp/ nocase ascii wide
                        $string12 = /\\HandleHijacker\.hpp/ nocase ascii wide
                        $string13 = /\\PoolParty\.cpp/ nocase ascii wide
                        $string14 = /\\PoolParty\.exe/ nocase ascii wide
                        $string15 = /\\PoolParty\.hpp/ nocase ascii wide
                        $string16 = /\\PoolParty\.sln/ nocase ascii wide
                        $string17 = /\\PoolParty\.vcxproj/ nocase ascii wide
                        $string18 = /\\PoolParty\-PoolParty\\/ nocase ascii wide
                        $string19 = /\\x24\\xC3\\C\:\\\\Windows\\\\System32\\\\calc\.exe\\x00/ nocase ascii wide
                        $string20 = "45D59D79-EF51-4A93-AAFA-2879FFC3A62C" nocase ascii wide
                        $string21 = "Allocated shellcode memory in the target process: " nocase ascii wide
                        $string22 = "Hijacked timer queue handle from the target process: " nocase ascii wide
                        $string23 = "Hijacked worker factory handle from the target process: " nocase ascii wide
                        $string24 = "PoolParty attack completed successfully" nocase ascii wide
                        $string25 = /PoolParty\.exe\s/ nocase ascii wide
                        $string26 = /PoolParty\-main\.zip/ nocase ascii wide
                        $string27 = /PoolParty\-PoolParty\.zip/ nocase ascii wide
                        $string28 = "SafeBreach-Labs/PoolParty" nocase ascii wide
                        $string29 = "Starting PoolParty attack against process id: " nocase ascii wide

    condition:
        any of them
}