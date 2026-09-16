rule Forensia
{
    meta:
        description = "Detection patterns for the tool 'Forensia' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Forensia"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sForensia\.exe/ nocase ascii wide
                        $string2 = /\/Forensia\.exe/ nocase ascii wide
                        $string3 = /\/Forensia\.git/ nocase ascii wide
                        $string4 = /\/forensia\.pdb/ nocase ascii wide
                        $string5 = "/Forensia/releases/download/ReleaseX64/" nocase ascii wide
                        $string6 = /\\Forensia\.exe/ nocase ascii wide
                        $string7 = /\\forensia\.pdb/ nocase ascii wide
                        $string8 = "10f86295406d71ec27ef38e6f0f9f4d8ddc14e65a662716de879373ffa7248ec" nocase ascii wide
                        $string9 = "17c3e93b910bc4a48b09772e49f98d877dd870cf81a66697a8d24896bd6a8525" nocase ascii wide
                        $string10 = "196c82b02658590978ac1649a859f15db1ebd9012027d9a80674241ecc003400" nocase ascii wide
                        $string11 = "1d259e77687bc50118ed0a0f6e2e1a1d62b21f39c3f9549b729a01e023773252" nocase ascii wide
                        $string12 = "3a5a1ef73fded6644e0c6b4967fb129ec3716b517b6ca8699d72e2e0fd3e49ec" nocase ascii wide
                        $string13 = "50376d47e0c921dfc85a5117735f9de297efd826fe152b2fc44d3aa4281e13c5" nocase ascii wide
                        $string14 = "510c6896ab176ad04a534ed48a3c74957ca929accbaf277ee1d678eac6bf3b36" nocase ascii wide
                        $string15 = "87135ab4-4cf7-454c-8830-38eb3ede1241" nocase ascii wide
                        $string16 = "8e8053c4ec1c1bebf984ba0e868361a87e5240993a6feec5ba3626a11f23cb87" nocase ascii wide
                        $string17 = "b1705ed5733748745497767e2a4855893131f76cbb4b28a58fddf89fa679b27b" nocase ascii wide
                        $string18 = "c933e37b3b281f081e395a20bb950a1a5130f839bf3477f0bf6fc62c1535591b" nocase ascii wide
                        $string19 = "Clearing Defender Quarantine Files" nocase ascii wide
                        $string20 = /Clearing\sShim\sCache\sData\.\.\./ nocase ascii wide
                        $string21 = /del\s\/F\s\/Q\s\%APPDATA\%\\\\Microsoft\\\\Windows\\\\Recent\\\\/ nocase ascii wide
                        $string22 = /del\s\/F\s\/Q\s\%APPDATA\%\\\\Microsoft\\\\Windows\\\\Recent\\\\AutomaticDestinations\\\\/ nocase ascii wide
                        $string23 = /del\s\/F\s\/Q\s\%APPDATA\%\\\\Microsoft\\\\Windows\\\\Recent\\\\CustomDestinations\\\\/ nocase ascii wide
                        $string24 = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\/ nocase ascii wide
                        $string25 = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\/ nocase ascii wide
                        $string26 = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\CustomDestinations\\/ nocase ascii wide
                        $string27 = /del\s\/F\s\/Q\sC\:\\\\Windows\\\\Prefetch\\\\/ nocase ascii wide
                        $string28 = /del\s\/F\s\/Q\sC\:\\Windows\\Prefetch\\/ nocase ascii wide
                        $string29 = /del\sC\:\\\\Windows\\\\AppCompat\\\\Programs\\\\RecentFileCache\.bcf/ nocase ascii wide
                        $string30 = /del\sC\:\\Windows\\AppCompat\\Programs\\RecentFileCache\.bcf/ nocase ascii wide
                        $string31 = /Deleting\sRecentFileCache\.bcf/ nocase ascii wide
                        $string32 = /Forensia\.exe\s\-D\s/ nocase ascii wide
                        $string33 = /fsutil\.exe\susn\sdeletejournal\s\/D\sC\:/ nocase ascii wide
                        $string34 = "PaulNorman01/Forensia" nocase ascii wide
                        $string35 = /rmdir\sC\:\\ProgramData\\Microsoft\\Windows\sDefender\\Quarantine\\Entries\s\/S/ nocase ascii wide
                        $string36 = /rmdir\sC\:\\ProgramData\\Microsoft\\Windows\sDefender\\Quarantine\\ResourceData\s\/S/ nocase ascii wide
                        $string37 = /rmdir\sC\:\\ProgramData\\Microsoft\\Windows\sDefender\\Quarantine\\Resources\s\/S/ nocase ascii wide
                        $string38 = "Switching To Event Tracing Disabler Module" nocase ascii wide
                        $string39 = "Switching To NTFS Last Access Time Disabler" nocase ascii wide
                        $string40 = "Switching To Prefetch Disabler" nocase ascii wide
                        $string41 = "Switching To ShellBag Remover" nocase ascii wide
                        $string42 = "Switching To USNJrnl Disabling Module" nocase ascii wide
                        $string43 = "Switching To Windows Event Log Disabler" nocase ascii wide

    condition:
        any of them
}