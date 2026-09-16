rule Quasar
{
    meta:
        description = "Detection patterns for the tool 'Quasar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Quasar"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " CN=Quasar Server CA" nocase ascii wide
                        $string2 = /\/Quasar\.git/ nocase ascii wide
                        $string3 = /\/Quasar\.v.{0,1000}\.zip/ nocase ascii wide
                        $string4 = "/Quasar/releases" nocase ascii wide
                        $string5 = /\\appdata\\roaming\\.{0,1000}\'DestPort\'\>4782\<\/Data\>/ nocase ascii wide
                        $string6 = /\\CurrentVersion\\Run\\Quasar\sClient\sStartup/ nocase ascii wide
                        $string7 = /\\Prefetch\\QUASAR\.EXE/ nocase ascii wide
                        $string8 = /\\Program\sFiles\\SubDir\\Client\.exe/ nocase ascii wide
                        $string9 = /\\Quasar\.Client\\/ nocase ascii wide
                        $string10 = /\\Quasar\.Common\\.{0,1000}\.cs/ nocase ascii wide
                        $string11 = /\\quasar\.p12/ nocase ascii wide
                        $string12 = /\\Quasar\.v.{0,1000}\.zip/ nocase ascii wide
                        $string13 = /\\Quasar\-master/ nocase ascii wide
                        $string14 = /\\Windows\\system32\\SubDir\\Client\.exe/ nocase ascii wide
                        $string15 = "14CA405B-8BAC-48AB-9FBA-8FB5DF88FD0D" nocase ascii wide
                        $string16 = "32A2A734-7429-47E6-A362-E344A19C0D85" nocase ascii wide
                        $string17 = "9F5CF56A-DDB2-4F40-AB99-2A1DC47588E1" nocase ascii wide
                        $string18 = /Backdoor\.Quasar/ nocase ascii wide
                        $string19 = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" nocase ascii wide
                        $string20 = "CFCD0759E20F29C399C9D4210BE614E4E020BEE8" nocase ascii wide
                        $string21 = "localhost:4782" nocase ascii wide
                        $string22 = /namespace\sQuasar\.Client/ nocase ascii wide
                        $string23 = /namespace\sQuasar\.Server/ nocase ascii wide
                        $string24 = "ping -n 10 localhost > nul" nocase ascii wide
                        $string25 = "Quasar Client Startup" nocase ascii wide
                        $string26 = /Quasar\sv.{0,1000}\\Client\-built\.exe/ nocase ascii wide
                        $string27 = /Quasar\.Client\./ nocase ascii wide
                        $string28 = /Quasar\.Common\.Tests\\/ nocase ascii wide
                        $string29 = /Quasar\.exe/ nocase ascii wide
                        $string30 = /Quasar\.Server/ nocase ascii wide
                        $string31 = /Quasar\.Server\\Program\.cs/ nocase ascii wide
                        $string32 = /Quasar\.sln/ nocase ascii wide
                        $string33 = /Quasar\.v1\.4\.1\.zip/ nocase ascii wide
                        $string34 = "quasar/Quasar" nocase ascii wide
                        $string35 = /Quasar\-master\.zip/ nocase ascii wide
                        $string36 = "QuasarRAT" nocase ascii wide
                        $string37 = "ylAo2kAlUS2kYkala!" nocase ascii wide

    condition:
        any of them
}