rule rule_ScreenConnect_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ScreenConnect' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScreenConnect"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ScreenConnect_greyware_tool_keyword = /\:8040\/SetupWizard\.aspx/ nocase ascii wide
                        $string2_ScreenConnect_greyware_tool_keyword = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\ScreenConnect\sClient\s\(/ nocase ascii wide
                        $string3_ScreenConnect_greyware_tool_keyword = /\\CurrentControlSet\\Services\\ScreenConnect\s/ nocase ascii wide
                        $string4_ScreenConnect_greyware_tool_keyword = /\\Documents\\ConnectWiseControl\\Files/ nocase ascii wide
                        $string5_ScreenConnect_greyware_tool_keyword = /\\InventoryApplicationFile\\screenconnect\.cl/ nocase ascii wide
                        $string6_ScreenConnect_greyware_tool_keyword = /\\InventoryApplicationFile\\screenconnect\.wi/ nocase ascii wide
                        $string7_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\sClient\s\(/ nocase ascii wide
                        $string8_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Client\.exe/ nocase ascii wide
                        $string9_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.ClientService\.exe/ nocase ascii wide
                        $string10_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
                        $string11_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Core\.dll/ nocase ascii wide
                        $string12_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.InstallerActions\.dll/ nocase ascii wide
                        $string13_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Windows\.dll/ nocase ascii wide
                        $string14_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
                        $string15_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
                        $string16_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\\Bin\\/ nocase ascii wide
                        $string17_ScreenConnect_greyware_tool_keyword = /\\TEMP\\ScreenConnect\\.{0,100}\.ps1/ nocase ascii wide
                        $string18_ScreenConnect_greyware_tool_keyword = /\\Temp\\ScreenConnect\\.{0,100}\\setup\.msi/ nocase ascii wide
                        $string19_ScreenConnect_greyware_tool_keyword = /\\Windows\\Temp\\ScreenConnect\\.{0,100}\.cmd/ nocase ascii wide
                        $string20_ScreenConnect_greyware_tool_keyword = /\\Windows\\Temp\\ScreenConnect\\.{0,100}\.ps1/ nocase ascii wide
                        $string21_ScreenConnect_greyware_tool_keyword = "<Data>ScreenConnect Software</Data>" nocase ascii wide
                        $string22_ScreenConnect_greyware_tool_keyword = "<Provider Name='ScreenConnect Security Manager'/>" nocase ascii wide
                        $string23_ScreenConnect_greyware_tool_keyword = "<Provider Name='ScreenConnect Web Server'/>" nocase ascii wide
                        $string24_ScreenConnect_greyware_tool_keyword = /cmd\.exe.{0,100}\\TEMP\\ScreenConnect\\.{0,100}\.cmd/ nocase ascii wide
                        $string25_ScreenConnect_greyware_tool_keyword = /https\:\/\/.{0,100}\.screenconnect\.com\/Bin\/.{0,100}\.exe/ nocase ascii wide
                        $string26_ScreenConnect_greyware_tool_keyword = /https\:\/\/.{0,100}\.screenconnect\.com\/Host/ nocase ascii wide
                        $string27_ScreenConnect_greyware_tool_keyword = /https\:\/\/cloud\.screenconnect\.com\/\#\/trialtoinstance\?cookieValue\=/ nocase ascii wide
                        $string28_ScreenConnect_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\ScreenConnect\sClient/ nocase ascii wide
                        $string29_ScreenConnect_greyware_tool_keyword = /\-relay\.screenconnect\.com/ nocase ascii wide
                        $string30_ScreenConnect_greyware_tool_keyword = "ScreenConnect Software" nocase ascii wide
                        $string31_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Client\.dll/ nocase ascii wide
                        $string32_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Client\.exe\.jar/ nocase ascii wide
                        $string33_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientService\.dll/ nocase ascii wide
                        $string34_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientService\.exe/ nocase ascii wide
                        $string35_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
                        $string36_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.CLIENTSETUP\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string37_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientUninstall\.vbs/ nocase ascii wide
                        $string38_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Core\.pdb/ nocase ascii wide
                        $string39_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Server\.dll/ nocase ascii wide
                        $string40_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Service\.exe/ nocase ascii wide
                        $string41_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.SERVICE\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string42_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
                        $string43_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.WINDOWSCLIENT\..{0,100}\.pf/ nocase ascii wide
                        $string44_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
                        $string45_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsInstaller\.dll/ nocase ascii wide
                        $string46_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,100}_Release\.msi/ nocase ascii wide
                        $string47_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,100}_Release\.tar\.gz/ nocase ascii wide
                        $string48_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,100}_Release\.zip/ nocase ascii wide
                        $string49_ScreenConnect_greyware_tool_keyword = /ScreenConnectClientNetworkDeployer\.exe/ nocase ascii wide
                        $string50_ScreenConnect_greyware_tool_keyword = /server.{0,100}\-relay\.screenconnect\.com/ nocase ascii wide
                        $string51_ScreenConnect_greyware_tool_keyword = /\-web\.screenconnect\.com/ nocase ascii wide
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