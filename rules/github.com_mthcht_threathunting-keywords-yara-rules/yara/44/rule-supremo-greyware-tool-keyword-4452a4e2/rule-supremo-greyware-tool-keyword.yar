rule rule_Supremo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Supremo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supremo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Supremo_greyware_tool_keyword = " start SupremoService" nocase ascii wide
                        $string2_Supremo_greyware_tool_keyword = /\sSupremo\.exe/ nocase ascii wide
                        $string3_Supremo_greyware_tool_keyword = /\/Supremo\.exe/ nocase ascii wide
                        $string4_Supremo_greyware_tool_keyword = /\\\\\.\\pipe\\Supremo/ nocase ascii wide
                        $string5_Supremo_greyware_tool_keyword = /\\Control\\SafeBoot\\Network\\SupremoService/ nocase ascii wide
                        $string6_Supremo_greyware_tool_keyword = /\\CurrentControlSet\\Services\\SupremoService/ nocase ascii wide
                        $string7_Supremo_greyware_tool_keyword = /\\Program\sFiles\\Supremo\\/ nocase ascii wide
                        $string8_Supremo_greyware_tool_keyword = /\\ProgramData\\SupremoRemoteDesktop/ nocase ascii wide
                        $string9_Supremo_greyware_tool_keyword = /\\SOFTWARE\\Supremo\\/ nocase ascii wide
                        $string10_Supremo_greyware_tool_keyword = /\\Software\\Supremo\\Printer\\/ nocase ascii wide
                        $string11_Supremo_greyware_tool_keyword = /\\SOFTWARE\\WOW6432Node\\Supremo\\/ nocase ascii wide
                        $string12_Supremo_greyware_tool_keyword = /\\Supremo\sRemote\sPrinter\\/ nocase ascii wide
                        $string13_Supremo_greyware_tool_keyword = /\\Supremo\.exe/ nocase ascii wide
                        $string14_Supremo_greyware_tool_keyword = /\\SUPREMO\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string15_Supremo_greyware_tool_keyword = /\\Supremo_Client_2/ nocase ascii wide
                        $string16_Supremo_greyware_tool_keyword = /\\Supremo_Helper_2/ nocase ascii wide
                        $string17_Supremo_greyware_tool_keyword = /\\Supremo_Service/ nocase ascii wide
                        $string18_Supremo_greyware_tool_keyword = /\\SupremoHelper\.exe/ nocase ascii wide
                        $string19_Supremo_greyware_tool_keyword = /\\SupremoRemoteDesktop\\/ nocase ascii wide
                        $string20_Supremo_greyware_tool_keyword = /\\Temp\\SupremoRemoteDesktop/ nocase ascii wide
                        $string21_Supremo_greyware_tool_keyword = "application/x-supremo" nocase ascii wide
                        $string22_Supremo_greyware_tool_keyword = /HKCR\\supremo\\shell\\/ nocase ascii wide
                        $string23_Supremo_greyware_tool_keyword = "supremo remote control" nocase ascii wide
                        $string24_Supremo_greyware_tool_keyword = /Supremo\.00\.Client\.log/ nocase ascii wide
                        $string25_Supremo_greyware_tool_keyword = /Supremo\.00\.FileTransfer\.log/ nocase ascii wide
                        $string26_Supremo_greyware_tool_keyword = /Supremo\.exe\s/ nocase ascii wide
                        $string27_Supremo_greyware_tool_keyword = /supremogw.{0,100}\.nanosystems\.it/ nocase ascii wide
                        $string28_Supremo_greyware_tool_keyword = /supremohelper\.exe/ nocase ascii wide
                        $string29_Supremo_greyware_tool_keyword = /SupremoRemoteDesktop\\History\.txt/ nocase ascii wide
                        $string30_Supremo_greyware_tool_keyword = /SupremoService\.00\.Service\.log/ nocase ascii wide
                        $string31_Supremo_greyware_tool_keyword = /SupremoService\.exe/ nocase ascii wide
                        $string32_Supremo_greyware_tool_keyword = /SupremoSystem\.exe/ nocase ascii wide
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