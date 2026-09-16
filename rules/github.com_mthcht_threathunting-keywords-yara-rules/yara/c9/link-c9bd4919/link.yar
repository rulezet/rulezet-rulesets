rule link
{
    meta:
        description = "Detection patterns for the tool 'link' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "link"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\skali\-install\.sh/ nocase ascii wide
                        $string2 = /\.\/kali\-install\.sh/
                        $string3 = /\.link\/links\/windows\/target\/x86_64\-pc\-windows\-gnu\/release\/link\.exe/ nocase ascii wide
                        $string4 = /\/\.link\/3rdparty\/SharpCollection/ nocase ascii wide
                        $string5 = /\/Stracciatella\/releases\/latest\/download\/Stracciatella\.exe/ nocase ascii wide
                        $string6 = /\\kali\-install\.sh/ nocase ascii wide
                        $string7 = /\\src\\links\\windows\\src\\evasion\.rs/ nocase ascii wide
                        $string8 = /execute\sPowerShell\swithout\spowershell\.exe/ nocase ascii wide
                        $string9 = /execute\-assembly\ssvchost\s.{0,1000}\.exe/ nocase ascii wide
                        $string10 = /execute\-pe\ssvchost\swhoami\.exe/ nocase ascii wide
                        $string11 = /github\.com\/postrequest\/link/ nocase ascii wide
                        $string12 = /link\-inject.{0,1000}inject\slink\sinto\sprocess/ nocase ascii wide
                        $string13 = /Out\-Minidump\.ps1/ nocase ascii wide
                        $string14 = /output\:\slink\.bin/ nocase ascii wide
                        $string15 = /output\:\slink\.dll/ nocase ascii wide
                        $string16 = "pip3 install pypykatz" nocase ascii wide
                        $string17 = /postrequest\/link\.git/ nocase ascii wide
                        $string18 = "pypykatz not installed" nocase ascii wide
                        $string19 = "sharp ADCollector" nocase ascii wide
                        $string20 = "sharp ADSearch" nocase ascii wide
                        $string21 = "sharp BetterSafetyKatz" nocase ascii wide
                        $string22 = "sharp init  download/update SharpCollection tools" nocase ascii wide
                        $string23 = "sharp InveighZero" nocase ascii wide
                        $string24 = "sharp SharpAllowedToAct" nocase ascii wide
                        $string25 = "sharp SharpAppLocker" nocase ascii wide
                        $string26 = "sharp SharpChisel" nocase ascii wide
                        $string27 = "sharp SharpChromium" nocase ascii wide
                        $string28 = "sharp SharpCrashEventLog " nocase ascii wide
                        $string29 = "sharp SharpKatz --Command logonpasswords" nocase ascii wide
                        $string30 = "sharp SharpMiniDump" nocase ascii wide
                        $string31 = "sharp Sharp-SMBExec " nocase ascii wide
                        $string32 = "sharp SharpSpray" nocase ascii wide
                        $string33 = "sharp SharpZeroLogon" nocase ascii wide
                        $string34 = "sharp StickyNotesExtract" nocase ascii wide
                        $string35 = "sharp winPEAS" nocase ascii wide
                        $string36 = /sharp_collection\.insert\(/ nocase ascii wide
                        $string37 = /SharpKatz\.exe/ nocase ascii wide

    condition:
        any of them
}