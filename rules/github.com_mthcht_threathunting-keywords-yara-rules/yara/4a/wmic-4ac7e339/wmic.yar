rule wmic
{
    meta:
        description = "Detection patterns for the tool 'wmic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmic"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sprocess\scall\screate\s.{0,100}cmd\.exe\s\/c\spowershell\.exe\s\-nop\s\-w\shidden\s\-c\s.{0,100}IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'https\:\/\// nocase ascii wide
                        $string2 = /\.exe\sshadowcopy\sdelete/ nocase ascii wide
                        $string3 = /\/NAMESPACE\:\\\\root\\Microsoft\\Windows\\Defender\sPATH\sMSFT_MpPreference\scall\sAdd\sExclusionExtension\=exe\sForce\=True/ nocase ascii wide
                        $string4 = /\\Temp\\.{0,100}\\ntds\.dit/ nocase ascii wide
                        $string5 = /\\Temp\\.{0,100}\\ntds\.jfm/ nocase ascii wide
                        $string6 = /\\Users\\Public\\.{0,100}ntds\.dit/ nocase ascii wide
                        $string7 = /\\Users\\Public\\.{0,100}ntds\.jfm/ nocase ascii wide
                        $string8 = /ac\si\sntds.{0,100}\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
                        $string9 = /cmd\s\s\/c\swmic\s\/node\:.{0,100}\sprocess\scall\screate\s\\"C\:\\programdata\\/ nocase ascii wide
                        $string10 = /cmd\s\s\/c\swmic\s\/node\:.{0,100}\sprocess\scall\screate\s\\"C\:\\Temp\\/ nocase ascii wide
                        $string11 = /cmd\s\s\/c\swmic\s\/node\:.{0,100}\sprocess\scall\screate\s\\"C\:\\users\\.{0,100}\\AppData\\Local\\Temp/ nocase ascii wide
                        $string12 = /cmd\s\s\/c\swmic\s\/node\:.{0,100}\sprocess\scall\screate\s\\"C\:\\users\\Public/ nocase ascii wide
                        $string13 = /cmd\.exe\s\/C\swmic\s\/node\:.{0,100}\s\/user\:.{0,100}\s\/password\:.{0,100}\sos\sget\scaption/ nocase ascii wide
                        $string14 = "process call create \"powershell enable-psremoting -force\"" nocase ascii wide
                        $string15 = /start\swmic\s\/node\:\@C\:\\.{0,100}\.txt\s\/user\:.{0,100}\/password\:.{0,100}\sprocess\scall\screate\s.{0,100}cmd\.exe\s\/c\sbitsadmin\s\/transfer\s.{0,100}\.exe\s/ nocase ascii wide
                        $string16 = /Win32_Shadowcopy\s\|\sForEach\-Object\s\{\$_\.Delete\(\)\;/ nocase ascii wide
                        $string17 = /wmic\s\/.{0,100}\s\/user\:administrator\sprocess\scall\screate\s.{0,100}cmd\.exe\s\/c\s/ nocase ascii wide
                        $string18 = /wmic\s\/node\:.{0,100}\s\/user\:.{0,100}\s\/password\:.{0,100}\sprocess\scall\screate\s\\"\\\\.{0,100}\\.{0,100}\.exe/ nocase ascii wide
                        $string19 = /wmic\s\/node\:.{0,100}\spath\sWin32_TerminalServiceSetting\swhere\sAllowTSConnections\=\\"0\\"\scall\sSetAllowTSConnections\s\\"1\\"/ nocase ascii wide
                        $string20 = /wmic\s\/node\:.{0,100}\..{0,100}\..{0,100}\..{0,100}computersystem\sget\susername/ nocase ascii wide
                        $string21 = /wmic\s\/node\:.{0,100}localhost.{0,100}computersystem\sget\susername/ nocase ascii wide
                        $string22 = /wmic\s\/node\:\{1\}\sprocess\scall\screate\s\\"rundll32\.exe\sC\:\\ProgramData\\/ nocase ascii wide
                        $string23 = "wmic computersystem get domain" nocase ascii wide
                        $string24 = /wmic\sprocess\scall\screate.{0,100}ntdsutil\s.{0,100}ac\si\sntds.{0,100}\sifm.{0,100}create\sfull/ nocase ascii wide
                        $string25 = "wmic process get commandline -all" nocase ascii wide
                        $string26 = "wmic process get commandline" nocase ascii wide
                        $string27 = "wmic product where \"name like '%Malwarebytes%'\" call uninstall /nointeractive" nocase ascii wide
                        $string28 = "wmic product where \"name like 'Malwarebytes%'\" call uninstall /nointeractive" nocase ascii wide
                        $string29 = "wmic service brief" nocase ascii wide
                        $string30 = "wmic service where \"caption like '%Sophos%'\" call stopservice" nocase ascii wide
                        $string31 = "wmic service where \"name like '%veeam%'\" call stopservice" nocase ascii wide
                        $string32 = "wmic service where \"name like 'acronisagent%'\" call stopservice" nocase ascii wide
                        $string33 = "wmic service where \"name like 'acrsch2svc%'\" call stopservice" nocase ascii wide
                        $string34 = "wmic service where \"name like 'agntsvc%'\" call stopservice" nocase ascii wide
                        $string35 = "wmic service where \"name like 'arsm%'\" call stopservice" nocase ascii wide
                        $string36 = "wmic service where \"name like 'backp%'\" call stopservice" nocase ascii wide
                        $string37 = "wmic service where \"name like 'backup%'\" call stopservice" nocase ascii wide
                        $string38 = "wmic service where \"name like 'cbservi%'\" call stopservice" nocase ascii wide
                        $string39 = "wmic service where \"name like 'cbvscserv%'\" call stopservice" nocase ascii wide
                        $string40 = "wmic service where \"name like 'shadowprotectsvc%'\" call stopservice" nocase ascii wide
                        $string41 = "wmic service where \"name like 'spxservice%'\" call stopservice" nocase ascii wide
                        $string42 = "wmic service where \"name like 'sqbcoreservice%'\" call stopservice" nocase ascii wide
                        $string43 = "wmic service where \"name like 'stc_endpt_svc%'\" call stopservice" nocase ascii wide
                        $string44 = "wmic service where \"name like 'storagecraft imagemanager%'\" call stopservice" nocase ascii wide
                        $string45 = "wmic service where \"name like 'veeam%'\" call stopservice" nocase ascii wide
                        $string46 = "wmic service where \"name like 'vsnapvss%'\" call stopservice" nocase ascii wide
                        $string47 = "wmic service where \"name like 'vssvc%'\" call stopservice" nocase ascii wide
                        $string48 = "wmic service where \"name like 'wbengine%'\" call stopservice" nocase ascii wide
                        $string49 = "wmic SHADOWCOPY /nointeractive" nocase ascii wide
                        $string50 = "wmic shadowcopy delete" nocase ascii wide
                        $string51 = "wmic useraccount get /ALL /format:csv" nocase ascii wide
                        $string52 = "wmic volume list brief" nocase ascii wide
                        $string53 = /wmic.{0,100}\/Namespace\:\\\\root\\SecurityCenter2\sPath\sAntiVirusProduct\sGet\sdisplayName/ nocase ascii wide
                        $string54 = /wmic\.exe\sprocess\scall\screate\s.{0,100}\.txt\:.{0,100}\.exe/ nocase ascii wide
                        $string55 = /wmic\.exe\sprocess\scall\screate\s.{0,100}cmd\s\/c\s/ nocase ascii wide
                        $string56 = /wmic\.exe\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
                        $string57 = /wmic\.exe\sshadowcopy\sdelete/ nocase ascii wide
                        $string58 = /WMIC\.exe\sshadowcopy\swhere\s.{0,100}ID\=.{0,100}\sdelete/ nocase ascii wide
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