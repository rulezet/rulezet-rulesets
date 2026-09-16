rule POSTDump
{
    meta:
        description = "Detection patterns for the tool 'POSTDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "POSTDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPostDump\.exe/ nocase ascii wide
                        $string2 = /\.exe\s\-\-signature\s\-\-driver/ nocase ascii wide
                        $string3 = /\/PostDump\.exe/ nocase ascii wide
                        $string4 = /\/POSTDump\.git/ nocase ascii wide
                        $string5 = /\\lsass\.dmp/ nocase ascii wide
                        $string6 = /\\POSTDump\.csproj/ nocase ascii wide
                        $string7 = /\\PostDump\.exe/ nocase ascii wide
                        $string8 = /\\POSTDump\.sln/ nocase ascii wide
                        $string9 = /\\POSTDump\\POSTDump\\/ nocase ascii wide
                        $string10 = /\\POSTMiniDump\\/ nocase ascii wide
                        $string11 = /ASR_bypass_to_dump_LSASS\.cs/ nocase ascii wide
                        $string12 = /copy\s.{0,1000}PROCEXP\.sys.{0,1000}C\:\\Windows\\System32\\WindowsPowershell\\/ nocase ascii wide
                        $string13 = /Done\!\sCheck\sfor\sexisting\slsass\.dmp\sfile\sinto\scurrent\sfolder/ nocase ascii wide
                        $string14 = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase ascii wide
                        $string15 = "Invoke-PostDump" nocase ascii wide
                        $string16 = "namespace POSTDump" nocase ascii wide
                        $string17 = "namespace POSTMiniDump" nocase ascii wide
                        $string18 = /POSTDump.{0,1000}PROCEXP\.sys/ nocase ascii wide
                        $string19 = /PostDump\.exe\s/ nocase ascii wide
                        $string20 = /POSTDump\.git/ nocase ascii wide
                        $string21 = /PostDump\.ps1/ nocase ascii wide
                        $string22 = /POSTDump\\Postdump\.cs/ nocase ascii wide
                        $string23 = /POSTDump\\PROCEXP\.sys/ nocase ascii wide
                        $string24 = "POSTDump-main" nocase ascii wide
                        $string25 = /POSTMiniDump\.Data/ nocase ascii wide
                        $string26 = /POSTMiniDump\.MiniDump/ nocase ascii wide
                        $string27 = /POSTMiniDump\.Utils/ nocase ascii wide
                        $string28 = /python3\sdump\-restore\.py/ nocase ascii wide
                        $string29 = "YOLOP0wn/POSTDump" nocase ascii wide

    condition:
        any of them
}