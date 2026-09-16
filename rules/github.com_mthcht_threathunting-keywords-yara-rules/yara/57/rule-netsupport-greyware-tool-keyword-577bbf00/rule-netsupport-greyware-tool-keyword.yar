rule rule_NetSupport_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetSupport' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSupport"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_NetSupport_greyware_tool_keyword = " /EV\"NetSupport School\"" nocase ascii wide
                        $string2_NetSupport_greyware_tool_keyword = /\/nspowershell\.exe/ nocase ascii wide
                        $string3_NetSupport_greyware_tool_keyword = /\/nssadmui\.exe/ nocase ascii wide
                        $string4_NetSupport_greyware_tool_keyword = /\/pcictlui\.exe/ nocase ascii wide
                        $string5_NetSupport_greyware_tool_keyword = /\/PCIDEPLY\.exe/ nocase ascii wide
                        $string6_NetSupport_greyware_tool_keyword = /\/Win7Taskbar\.dll/ nocase ascii wide
                        $string7_NetSupport_greyware_tool_keyword = /\\ADM\sTemplates\\ADMX\\.{0,100}\.admx/ nocase ascii wide
                        $string8_NetSupport_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,100}\\NSM\.LIC/ nocase ascii wide
                        $string9_NetSupport_greyware_tool_keyword = /\\AppData\\Roaming\\.{0,100}\\remote\.nsm/ nocase ascii wide
                        $string10_NetSupport_greyware_tool_keyword = /\\AppData\\Roaming\\NetSupport\\/ nocase ascii wide
                        $string11_NetSupport_greyware_tool_keyword = /\\NETSUP\~1\\PCIShellExt64\.dll/ nocase ascii wide
                        $string12_NetSupport_greyware_tool_keyword = /\\NetSupport\sLtd\\Client32/ nocase ascii wide
                        $string13_NetSupport_greyware_tool_keyword = /\\NetSupport\sLtd\\PCICTL/ nocase ascii wide
                        $string14_NetSupport_greyware_tool_keyword = /\\netsupport\smanager\\/ nocase ascii wide
                        $string15_NetSupport_greyware_tool_keyword = /\\NetSupport\sSchool\sConsole/ nocase ascii wide
                        $string16_NetSupport_greyware_tool_keyword = /\\NetSupport\sSchool\\/ nocase ascii wide
                        $string17_NetSupport_greyware_tool_keyword = /\\NetSupport\sSchool\\NetSupport/ nocase ascii wide
                        $string18_NetSupport_greyware_tool_keyword = /\\nspowershell\.exe/ nocase ascii wide
                        $string19_NetSupport_greyware_tool_keyword = /\\nssadmui\.exe/ nocase ascii wide
                        $string20_NetSupport_greyware_tool_keyword = /\\pcicfgui_client\.exe/ nocase ascii wide
                        $string21_NetSupport_greyware_tool_keyword = /\\pciconn\.exe/ nocase ascii wide
                        $string22_NetSupport_greyware_tool_keyword = /\\PCICTL\\ConfigList\\Standard\\UI\\/ nocase ascii wide
                        $string23_NetSupport_greyware_tool_keyword = /\\pcictlui\.exe/ nocase ascii wide
                        $string24_NetSupport_greyware_tool_keyword = /\\PCIDEPLY\.exe/ nocase ascii wide
                        $string25_NetSupport_greyware_tool_keyword = /\\PCINSSCD\.exe/ nocase ascii wide
                        $string26_NetSupport_greyware_tool_keyword = /\\PCINSSUI\.exe/ nocase ascii wide
                        $string27_NetSupport_greyware_tool_keyword = /\\PCISCRUI\.exe/ nocase ascii wide
                        $string28_NetSupport_greyware_tool_keyword = /\\PCIShellExt64\.dll/ nocase ascii wide
                        $string29_NetSupport_greyware_tool_keyword = /\\Scripts\\CreateRegKey\.scp/ nocase ascii wide
                        $string30_NetSupport_greyware_tool_keyword = /\\Scripts\\DirLst\.log/ nocase ascii wide
                        $string31_NetSupport_greyware_tool_keyword = /\\Scripts\\DirLst\.scp/ nocase ascii wide
                        $string32_NetSupport_greyware_tool_keyword = /\\Scripts\\DrvSize\.scp/ nocase ascii wide
                        $string33_NetSupport_greyware_tool_keyword = /\\Scripts\\writetofile\.scp/ nocase ascii wide
                        $string34_NetSupport_greyware_tool_keyword = /\\Software\\NetSupport\sLtd\\/ nocase ascii wide
                        $string35_NetSupport_greyware_tool_keyword = /\\Start\sMenu\\Programs\\NetSupport/ nocase ascii wide
                        $string36_NetSupport_greyware_tool_keyword = /\\Win7Taskbar\.dll/ nocase ascii wide
                        $string37_NetSupport_greyware_tool_keyword = "_NetSupport_NetSupport Manager_" nocase ascii wide
                        $string38_NetSupport_greyware_tool_keyword = "=NetSupport Client_deleteme" nocase ascii wide
                        $string39_NetSupport_greyware_tool_keyword = ">NetSupport Client Application</" nocase ascii wide
                        $string40_NetSupport_greyware_tool_keyword = /\>NETSUPPORT\sLTD\.\<\// nocase ascii wide
                        $string41_NetSupport_greyware_tool_keyword = ">NetSupport Ltd</" nocase ascii wide
                        $string42_NetSupport_greyware_tool_keyword = ">NetSupport Remote Control</" nocase ascii wide
                        $string43_NetSupport_greyware_tool_keyword = ">NetSupport remote Control</" nocase ascii wide
                        $string44_NetSupport_greyware_tool_keyword = /activate\.netsupportsoftware\.com/ nocase ascii wide
                        $string45_NetSupport_greyware_tool_keyword = "Company'>NetSupport Ltd</" nocase ascii wide
                        $string46_NetSupport_greyware_tool_keyword = /geo\.netsupportsoftware\.com/ nocase ascii wide
                        $string47_NetSupport_greyware_tool_keyword = /HKCR\\nsm\\shell\\open\\command/ nocase ascii wide
                        $string48_NetSupport_greyware_tool_keyword = /HKCR\\NSScriptFile\\/ nocase ascii wide
                        $string49_NetSupport_greyware_tool_keyword = /HKLM\\System\\CurrentControlSet\\Services\\Client32/ nocase ascii wide
                        $string50_NetSupport_greyware_tool_keyword = /https\:\/\/nsproducts\.azureedge\.net\/nsm\-.{0,100}\/NetSupport/ nocase ascii wide
                        $string51_NetSupport_greyware_tool_keyword = "NetSupport Audio Sample Source Filter" nocase ascii wide
                        $string52_NetSupport_greyware_tool_keyword = "NetSupport Bitmap Source Filter" nocase ascii wide
                        $string53_NetSupport_greyware_tool_keyword = "NetSupport Manager -- Installation " nocase ascii wide
                        $string54_NetSupport_greyware_tool_keyword = /NetSupport\sManager\s\(1\)\.msi/ nocase ascii wide
                        $string55_NetSupport_greyware_tool_keyword = /NetSupport\sManager\.msi/ nocase ascii wide
                        $string56_NetSupport_greyware_tool_keyword = /NetSupport\%20Manager\.msi/ nocase ascii wide
                        $string57_NetSupport_greyware_tool_keyword = /netsupport.{0,100}\\PCISA\.exe/ nocase ascii wide
                        $string58_NetSupport_greyware_tool_keyword = /netsupport.{0,100}\\runscrip\.exe/ nocase ascii wide
                        $string59_NetSupport_greyware_tool_keyword = /netsupport.{0,100}\\supporttool\.exe/ nocase ascii wide
                        $string60_NetSupport_greyware_tool_keyword = /NetSupport_Client_machine\.adml/ nocase ascii wide
                        $string61_NetSupport_greyware_tool_keyword = /NetSupport_Control_Machine\.adml/ nocase ascii wide
                        $string62_NetSupport_greyware_tool_keyword = /NSM_Control_Machine\.adm/ nocase ascii wide
                        $string63_NetSupport_greyware_tool_keyword = /pcicfgui_client\.exe.{0,100}\\Client32\.ini/ nocase ascii wide
                        $string64_NetSupport_greyware_tool_keyword = /program\sfiles.{0,100}\\netsupport\\/ nocase ascii wide
                        $string65_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Client<" nocase ascii wide
                        $string66_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Control<" nocase ascii wide
                        $string67_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Deploy<" nocase ascii wide
                        $string68_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Gateway<" nocase ascii wide
                        $string69_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Group Leader<" nocase ascii wide
                        $string70_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Run Script<" nocase ascii wide
                        $string71_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Script Editor<" nocase ascii wide
                        $string72_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Scripting Agent<" nocase ascii wide
                        $string73_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Tech Console<" nocase ascii wide
                        $string74_NetSupport_greyware_tool_keyword = "'RuleName'>NetSupport Tutor<" nocase ascii wide
                        $string75_NetSupport_greyware_tool_keyword = /WindowsStoreAppExporter\.exe/ nocase ascii wide
                        $string76_NetSupport_greyware_tool_keyword = /winst64\.exe.{0,100}\s\/q\s\/q\s\/ex\s\/i/ nocase ascii wide
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