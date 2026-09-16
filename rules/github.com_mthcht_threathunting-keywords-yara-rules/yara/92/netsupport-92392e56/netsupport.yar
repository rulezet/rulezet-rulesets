rule NetSupport
{
    meta:
        description = "Detection patterns for the tool 'NetSupport' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSupport"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " /EV\"NetSupport School\"" nocase ascii wide
                        $string2 = /\/nspowershell\.exe/ nocase ascii wide
                        $string3 = /\/nssadmui\.exe/ nocase ascii wide
                        $string4 = /\/pcictlui\.exe/ nocase ascii wide
                        $string5 = /\/PCIDEPLY\.exe/ nocase ascii wide
                        $string6 = /\/Win7Taskbar\.dll/ nocase ascii wide
                        $string7 = /\\ADM\sTemplates\\ADMX\\.{0,100}\.admx/ nocase ascii wide
                        $string8 = /\\AppData\\Local\\Temp\\.{0,100}\\NSM\.LIC/ nocase ascii wide
                        $string9 = /\\AppData\\Roaming\\.{0,100}\\remote\.nsm/ nocase ascii wide
                        $string10 = /\\AppData\\Roaming\\NetSupport\\/ nocase ascii wide
                        $string11 = /\\NETSUP\~1\\PCIShellExt64\.dll/ nocase ascii wide
                        $string12 = /\\NetSupport\sLtd\\Client32/ nocase ascii wide
                        $string13 = /\\NetSupport\sLtd\\PCICTL/ nocase ascii wide
                        $string14 = /\\netsupport\smanager\\/ nocase ascii wide
                        $string15 = /\\NetSupport\sSchool\sConsole/ nocase ascii wide
                        $string16 = /\\NetSupport\sSchool\\/ nocase ascii wide
                        $string17 = /\\NetSupport\sSchool\\NetSupport/ nocase ascii wide
                        $string18 = /\\nspowershell\.exe/ nocase ascii wide
                        $string19 = /\\nssadmui\.exe/ nocase ascii wide
                        $string20 = /\\pcicfgui_client\.exe/ nocase ascii wide
                        $string21 = /\\pciconn\.exe/ nocase ascii wide
                        $string22 = /\\PCICTL\\ConfigList\\Standard\\UI\\/ nocase ascii wide
                        $string23 = /\\pcictlui\.exe/ nocase ascii wide
                        $string24 = /\\PCIDEPLY\.exe/ nocase ascii wide
                        $string25 = /\\PCINSSCD\.exe/ nocase ascii wide
                        $string26 = /\\PCINSSUI\.exe/ nocase ascii wide
                        $string27 = /\\PCISCRUI\.exe/ nocase ascii wide
                        $string28 = /\\PCIShellExt64\.dll/ nocase ascii wide
                        $string29 = /\\Scripts\\CreateRegKey\.scp/ nocase ascii wide
                        $string30 = /\\Scripts\\DirLst\.log/ nocase ascii wide
                        $string31 = /\\Scripts\\DirLst\.scp/ nocase ascii wide
                        $string32 = /\\Scripts\\DrvSize\.scp/ nocase ascii wide
                        $string33 = /\\Scripts\\writetofile\.scp/ nocase ascii wide
                        $string34 = /\\Software\\NetSupport\sLtd\\/ nocase ascii wide
                        $string35 = /\\Start\sMenu\\Programs\\NetSupport/ nocase ascii wide
                        $string36 = /\\Win7Taskbar\.dll/ nocase ascii wide
                        $string37 = "_NetSupport_NetSupport Manager_" nocase ascii wide
                        $string38 = "=NetSupport Client_deleteme" nocase ascii wide
                        $string39 = ">NetSupport Client Application</" nocase ascii wide
                        $string40 = /\>NETSUPPORT\sLTD\.\<\// nocase ascii wide
                        $string41 = ">NetSupport Ltd</" nocase ascii wide
                        $string42 = ">NetSupport Remote Control</" nocase ascii wide
                        $string43 = ">NetSupport remote Control</" nocase ascii wide
                        $string44 = /activate\.netsupportsoftware\.com/ nocase ascii wide
                        $string45 = "Company'>NetSupport Ltd</" nocase ascii wide
                        $string46 = /geo\.netsupportsoftware\.com/ nocase ascii wide
                        $string47 = /HKCR\\nsm\\shell\\open\\command/ nocase ascii wide
                        $string48 = /HKCR\\NSScriptFile\\/ nocase ascii wide
                        $string49 = /HKLM\\System\\CurrentControlSet\\Services\\Client32/ nocase ascii wide
                        $string50 = /https\:\/\/nsproducts\.azureedge\.net\/nsm\-.{0,100}\/NetSupport/ nocase ascii wide
                        $string51 = "NetSupport Audio Sample Source Filter" nocase ascii wide
                        $string52 = "NetSupport Bitmap Source Filter" nocase ascii wide
                        $string53 = "NetSupport Manager -- Installation " nocase ascii wide
                        $string54 = /NetSupport\sManager\s\(1\)\.msi/ nocase ascii wide
                        $string55 = /NetSupport\sManager\.msi/ nocase ascii wide
                        $string56 = /NetSupport\%20Manager\.msi/ nocase ascii wide
                        $string57 = /netsupport.{0,100}\\PCISA\.exe/ nocase ascii wide
                        $string58 = /netsupport.{0,100}\\runscrip\.exe/ nocase ascii wide
                        $string59 = /netsupport.{0,100}\\supporttool\.exe/ nocase ascii wide
                        $string60 = /NetSupport_Client_machine\.adml/ nocase ascii wide
                        $string61 = /NetSupport_Control_Machine\.adml/ nocase ascii wide
                        $string62 = /NSM_Control_Machine\.adm/ nocase ascii wide
                        $string63 = /pcicfgui_client\.exe.{0,100}\\Client32\.ini/ nocase ascii wide
                        $string64 = /program\sfiles.{0,100}\\netsupport\\/ nocase ascii wide
                        $string65 = "'RuleName'>NetSupport Client<" nocase ascii wide
                        $string66 = "'RuleName'>NetSupport Control<" nocase ascii wide
                        $string67 = "'RuleName'>NetSupport Deploy<" nocase ascii wide
                        $string68 = "'RuleName'>NetSupport Gateway<" nocase ascii wide
                        $string69 = "'RuleName'>NetSupport Group Leader<" nocase ascii wide
                        $string70 = "'RuleName'>NetSupport Run Script<" nocase ascii wide
                        $string71 = "'RuleName'>NetSupport Script Editor<" nocase ascii wide
                        $string72 = "'RuleName'>NetSupport Scripting Agent<" nocase ascii wide
                        $string73 = "'RuleName'>NetSupport Tech Console<" nocase ascii wide
                        $string74 = "'RuleName'>NetSupport Tutor<" nocase ascii wide
                        $string75 = /WindowsStoreAppExporter\.exe/ nocase ascii wide
                        $string76 = /winst64\.exe.{0,100}\s\/q\s\/q\s\/ex\s\/i/ nocase ascii wide
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