rule RedPersist
{
    meta:
        description = "Detection patterns for the tool 'RedPersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedPersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-\-eventviewer\s.{0,1000}\.exe/ nocase ascii wide
                        $string2 = /\.exe\s\-\-pwsh\s.{0,1000}\.ps1\s.{0,1000}\.exe/ nocase ascii wide
                        $string3 = /\.exe\s\-\-schedule\s.{0,1000}\s.{0,1000}\.exe/ nocase ascii wide
                        $string4 = /\.exe\s\-\-screensaver\s.{0,1000}\:\\.{0,1000}\.exe/ nocase ascii wide
                        $string5 = /\.exe\s\-\-startup\s.{0,1000}\:\\.{0,1000}\.exe/ nocase ascii wide
                        $string6 = /\.exe\s\-\-winlogon\s.{0,1000}\s.{0,1000}\:\\.{0,1000}\.exe/ nocase ascii wide
                        $string7 = /\.exe\s\-\-wmi\s.{0,1000}\:\\.{0,1000}\.exe/ nocase ascii wide
                        $string8 = /\/RedPersist\.exe/ nocase ascii wide
                        $string9 = /\/RedPersist\.git/ nocase ascii wide
                        $string10 = /\\RedPersist\.exe/ nocase ascii wide
                        $string11 = /\\RedPersist\.pdb/ nocase ascii wide
                        $string12 = /\\RedPersist\.sln/ nocase ascii wide
                        $string13 = /\\RedPersist\-main\\/ nocase ascii wide
                        $string14 = /\]\sEventviewer\sPersistence\screated/ nocase ascii wide
                        $string15 = /\]\sExtension\sHijacking\sPersistence\screated/ nocase ascii wide
                        $string16 = /\]\sPowershell\sPersistence\screated/ nocase ascii wide
                        $string17 = /\]\sScreensaver\sPersistence\screated/ nocase ascii wide
                        $string18 = /\]\sStartup\sPersistence\screated/ nocase ascii wide
                        $string19 = /\]\sUserInitMprLogonScript\sPersistence\screated/ nocase ascii wide
                        $string20 = "BD745A5E-A1E9-4FDD-A15B-E9F303A625AE" nocase ascii wide
                        $string21 = "bd745a5e-a1e9-4fdd-a15b-e9f303a625ae" nocase ascii wide
                        $string22 = "Hello From sadsad Team" nocase ascii wide
                        $string23 = "mertdas/RedPersist" nocase ascii wide
                        $string24 = /namespace\sRedPersist\.Persist/ nocase ascii wide
                        $string25 = /Persist\\autorun\.cs/ nocase ascii wide
                        $string26 = /Persist\\eventviewer\.cs/ nocase ascii wide
                        $string27 = /Persist\\powershell\.cs/ nocase ascii wide
                        $string28 = /Persist\\screensaver\.cs/ nocase ascii wide
                        $string29 = /Persist\\startup\.cs/ nocase ascii wide
                        $string30 = /Persist\\winlogon\.cs/ nocase ascii wide

    condition:
        any of them
}