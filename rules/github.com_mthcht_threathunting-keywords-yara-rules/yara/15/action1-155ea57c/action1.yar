rule action1
{
    meta:
        description = "Detection patterns for the tool 'action1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "action1"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/action1_agent\(My_Organization\)\.msi/ nocase ascii wide
                        $string2 = /\\Action1\\7z\.dll/ nocase ascii wide
                        $string3 = /\\Action1\\Agent\\Certificate/ nocase ascii wide
                        $string4 = /\\Action1\\CrashDumps/ nocase ascii wide
                        $string5 = /\\Action1\\package_downloads/ nocase ascii wide
                        $string6 = /\\Action1\\scripts\\Run_PowerShell_/ nocase ascii wide
                        $string7 = /\\action1_agent\(My_Organization\)\.msi/ nocase ascii wide
                        $string8 = /\\ACTION1_AGENT\.EXE\-/ nocase ascii wide
                        $string9 = /\\action1_log_.{0,100}\.log/ nocase ascii wide
                        $string10 = /\\Windows\\Action1\\scripts\\/ nocase ascii wide
                        $string11 = "_renamed_by_Action1" nocase ascii wide
                        $string12 = /a1\-server\-prod\-even\.action1\.com/ nocase ascii wide
                        $string13 = "Action1 Corporation" nocase ascii wide
                        $string14 = "Action1 Endpoint Security" nocase ascii wide
                        $string15 = /Action1.{0,100}\'DestinationPort\'\>22543/ nocase ascii wide
                        $string16 = /Action1\\batch_data\\Run_Script__/ nocase ascii wide
                        $string17 = /Action1\\first_install\.tmp/ nocase ascii wide
                        $string18 = /Action1\\what_is_this\.txt/ nocase ascii wide
                        $string19 = /action1_agent\.exe/ nocase ascii wide
                        $string20 = /action1_agent\.exe\.connection/ nocase ascii wide
                        $string21 = /action1_remote\.exe/ nocase ascii wide
                        $string22 = /action1_update\.exe/ nocase ascii wide
                        $string23 = /C\:\\Windows\\Action1\\/ nocase ascii wide
                        $string24 = /C\:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Action1/ nocase ascii wide
                        $string25 = "'Company'>Action1 Corporation" nocase ascii wide
                        $string26 = /CurrentControlSet\\Services\\A1Agent/ nocase ascii wide
                        $string27 = /https\:\/\/app\.action1\.com\/agent\/.{0,100}\/Windows\/.{0,100}\.msi/ nocase ascii wide
                        $string28 = /InventoryApplicationFile\\action1_agent\.ex/ nocase ascii wide
                        $string29 = /InventoryApplicationFile\\action1_remote\.e/ nocase ascii wide
                        $string30 = /server\.action1\.com/ nocase ascii wide
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