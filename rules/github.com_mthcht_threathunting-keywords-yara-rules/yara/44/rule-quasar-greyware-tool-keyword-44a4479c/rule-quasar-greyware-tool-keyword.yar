rule rule_Quasar_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Quasar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Quasar"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Quasar_greyware_tool_keyword = " CN=Quasar Server CA" nocase ascii wide
                        $string2_Quasar_greyware_tool_keyword = /\/Quasar\.git/ nocase ascii wide
                        $string3_Quasar_greyware_tool_keyword = /\/Quasar\.v.{0,100}\.zip/ nocase ascii wide
                        $string4_Quasar_greyware_tool_keyword = "/Quasar/releases" nocase ascii wide
                        $string5_Quasar_greyware_tool_keyword = /\\appdata\\roaming\\.{0,100}\'DestPort\'\>4782\<\/Data\>/ nocase ascii wide
                        $string6_Quasar_greyware_tool_keyword = /\\CurrentVersion\\Run\\Quasar\sClient\sStartup/ nocase ascii wide
                        $string7_Quasar_greyware_tool_keyword = /\\Prefetch\\QUASAR\.EXE/ nocase ascii wide
                        $string8_Quasar_greyware_tool_keyword = /\\Program\sFiles\\SubDir\\Client\.exe/ nocase ascii wide
                        $string9_Quasar_greyware_tool_keyword = /\\Quasar\.Client\\/ nocase ascii wide
                        $string10_Quasar_greyware_tool_keyword = /\\Quasar\.Common\\.{0,100}\.cs/ nocase ascii wide
                        $string11_Quasar_greyware_tool_keyword = /\\quasar\.p12/ nocase ascii wide
                        $string12_Quasar_greyware_tool_keyword = /\\Quasar\.v.{0,100}\.zip/ nocase ascii wide
                        $string13_Quasar_greyware_tool_keyword = /\\Quasar\-master/ nocase ascii wide
                        $string14_Quasar_greyware_tool_keyword = /\\Windows\\system32\\SubDir\\Client\.exe/ nocase ascii wide
                        $string15_Quasar_greyware_tool_keyword = "14CA405B-8BAC-48AB-9FBA-8FB5DF88FD0D" nocase ascii wide
                        $string16_Quasar_greyware_tool_keyword = "32A2A734-7429-47E6-A362-E344A19C0D85" nocase ascii wide
                        $string17_Quasar_greyware_tool_keyword = "9F5CF56A-DDB2-4F40-AB99-2A1DC47588E1" nocase ascii wide
                        $string18_Quasar_greyware_tool_keyword = /Backdoor\.Quasar/ nocase ascii wide
                        $string19_Quasar_greyware_tool_keyword = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" nocase ascii wide
                        $string20_Quasar_greyware_tool_keyword = "CFCD0759E20F29C399C9D4210BE614E4E020BEE8" nocase ascii wide
                        $string21_Quasar_greyware_tool_keyword = "localhost:4782" nocase ascii wide
                        $string22_Quasar_greyware_tool_keyword = /namespace\sQuasar\.Client/ nocase ascii wide
                        $string23_Quasar_greyware_tool_keyword = /namespace\sQuasar\.Server/ nocase ascii wide
                        $string24_Quasar_greyware_tool_keyword = "ping -n 10 localhost > nul" nocase ascii wide
                        $string25_Quasar_greyware_tool_keyword = "Quasar Client Startup" nocase ascii wide
                        $string26_Quasar_greyware_tool_keyword = /Quasar\sv.{0,100}\\Client\-built\.exe/ nocase ascii wide
                        $string27_Quasar_greyware_tool_keyword = /Quasar\.Client\./ nocase ascii wide
                        $string28_Quasar_greyware_tool_keyword = /Quasar\.Common\.Tests\\/ nocase ascii wide
                        $string29_Quasar_greyware_tool_keyword = /Quasar\.exe/ nocase ascii wide
                        $string30_Quasar_greyware_tool_keyword = /Quasar\.Server/ nocase ascii wide
                        $string31_Quasar_greyware_tool_keyword = /Quasar\.Server\\Program\.cs/ nocase ascii wide
                        $string32_Quasar_greyware_tool_keyword = /Quasar\.sln/ nocase ascii wide
                        $string33_Quasar_greyware_tool_keyword = /Quasar\.v1\.4\.1\.zip/ nocase ascii wide
                        $string34_Quasar_greyware_tool_keyword = "quasar/Quasar" nocase ascii wide
                        $string35_Quasar_greyware_tool_keyword = /Quasar\-master\.zip/ nocase ascii wide
                        $string36_Quasar_greyware_tool_keyword = "QuasarRAT" nocase ascii wide
                        $string37_Quasar_greyware_tool_keyword = "ylAo2kAlUS2kYkala!" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}