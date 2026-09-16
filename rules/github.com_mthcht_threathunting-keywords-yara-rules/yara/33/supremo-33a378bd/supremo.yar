rule Supremo
{
    meta:
        description = "Detection patterns for the tool 'Supremo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supremo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " start SupremoService" nocase ascii wide
                        $string2 = /\sSupremo\.exe/ nocase ascii wide
                        $string3 = /\/Supremo\.exe/ nocase ascii wide
                        $string4 = /\\\\\.\\pipe\\Supremo/ nocase ascii wide
                        $string5 = /\\Control\\SafeBoot\\Network\\SupremoService/ nocase ascii wide
                        $string6 = /\\CurrentControlSet\\Services\\SupremoService/ nocase ascii wide
                        $string7 = /\\Program\sFiles\\Supremo\\/ nocase ascii wide
                        $string8 = /\\ProgramData\\SupremoRemoteDesktop/ nocase ascii wide
                        $string9 = /\\SOFTWARE\\Supremo\\/ nocase ascii wide
                        $string10 = /\\Software\\Supremo\\Printer\\/ nocase ascii wide
                        $string11 = /\\SOFTWARE\\WOW6432Node\\Supremo\\/ nocase ascii wide
                        $string12 = /\\Supremo\sRemote\sPrinter\\/ nocase ascii wide
                        $string13 = /\\Supremo\.exe/ nocase ascii wide
                        $string14 = /\\SUPREMO\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string15 = /\\Supremo_Client_2/ nocase ascii wide
                        $string16 = /\\Supremo_Helper_2/ nocase ascii wide
                        $string17 = /\\Supremo_Service/ nocase ascii wide
                        $string18 = /\\SupremoHelper\.exe/ nocase ascii wide
                        $string19 = /\\SupremoRemoteDesktop\\/ nocase ascii wide
                        $string20 = /\\Temp\\SupremoRemoteDesktop/ nocase ascii wide
                        $string21 = "application/x-supremo" nocase ascii wide
                        $string22 = /HKCR\\supremo\\shell\\/ nocase ascii wide
                        $string23 = "supremo remote control" nocase ascii wide
                        $string24 = /Supremo\.00\.Client\.log/ nocase ascii wide
                        $string25 = /Supremo\.00\.FileTransfer\.log/ nocase ascii wide
                        $string26 = /Supremo\.exe\s/ nocase ascii wide
                        $string27 = /supremogw.{0,100}\.nanosystems\.it/ nocase ascii wide
                        $string28 = /supremohelper\.exe/ nocase ascii wide
                        $string29 = /SupremoRemoteDesktop\\History\.txt/ nocase ascii wide
                        $string30 = /SupremoService\.00\.Service\.log/ nocase ascii wide
                        $string31 = /SupremoService\.exe/ nocase ascii wide
                        $string32 = /SupremoSystem\.exe/ nocase ascii wide
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