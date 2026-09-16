rule rule_koadic_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'koadic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "koadic"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_koadic_offensive_tool_keyword = /\sComputerDefaults\.exe/ nocase ascii wide
                        $string2_koadic_offensive_tool_keyword = /\score\.payload\s/ nocase ascii wide
                        $string3_koadic_offensive_tool_keyword = /\score\.stager\s/ nocase ascii wide
                        $string4_koadic_offensive_tool_keyword = " impacket" nocase ascii wide
                        $string5_koadic_offensive_tool_keyword = " pypykatz" nocase ascii wide
                        $string6_koadic_offensive_tool_keyword = /\.\/koadic/
                        $string7_koadic_offensive_tool_keyword = /\/bitsadmin\/bitsadmin\.cmd/ nocase ascii wide
                        $string8_koadic_offensive_tool_keyword = /\/createstager\.py/ nocase ascii wide
                        $string9_koadic_offensive_tool_keyword = "/enum_domain_info" nocase ascii wide
                        $string10_koadic_offensive_tool_keyword = "/exec_psexec" nocase ascii wide
                        $string11_koadic_offensive_tool_keyword = "/exec_wmi" nocase ascii wide
                        $string12_koadic_offensive_tool_keyword = "/hashdump_dc" nocase ascii wide
                        $string13_koadic_offensive_tool_keyword = "/implant/elevate/" nocase ascii wide
                        $string14_koadic_offensive_tool_keyword = /\/killav\.py/ nocase ascii wide
                        $string15_koadic_offensive_tool_keyword = "/Koadic" nocase ascii wide
                        $string16_koadic_offensive_tool_keyword = /\/koadic\.git/ nocase ascii wide
                        $string17_koadic_offensive_tool_keyword = "/loot_finder" nocase ascii wide
                        $string18_koadic_offensive_tool_keyword = "/manage/exec_cmd" nocase ascii wide
                        $string19_koadic_offensive_tool_keyword = "/mimishim/" nocase ascii wide
                        $string20_koadic_offensive_tool_keyword = /\/mshta\.cmd/ nocase ascii wide
                        $string21_koadic_offensive_tool_keyword = /\/mshtajs\.cmd/ nocase ascii wide
                        $string22_koadic_offensive_tool_keyword = "/phishing/password_box" nocase ascii wide
                        $string23_koadic_offensive_tool_keyword = /\/regsvr\.cmd/ nocase ascii wide
                        $string24_koadic_offensive_tool_keyword = /\/rundll32\.cmd/ nocase ascii wide
                        $string25_koadic_offensive_tool_keyword = "/rundll32_js" nocase ascii wide
                        $string26_koadic_offensive_tool_keyword = "/shellcode_excel" nocase ascii wide
                        $string27_koadic_offensive_tool_keyword = /\/stager\/powershell\.py/ nocase ascii wide
                        $string28_koadic_offensive_tool_keyword = /\/stager\/powershell\/payload\.ps1/ nocase ascii wide
                        $string29_koadic_offensive_tool_keyword = /\/Tash\.dll/ nocase ascii wide
                        $string30_koadic_offensive_tool_keyword = /\/TashClient\./ nocase ascii wide
                        $string31_koadic_offensive_tool_keyword = /\/TashLoader\./ nocase ascii wide
                        $string32_koadic_offensive_tool_keyword = /\/wmi\.dropper/ nocase ascii wide
                        $string33_koadic_offensive_tool_keyword = "AddUserImplant" nocase ascii wide
                        $string34_koadic_offensive_tool_keyword = "BitsadminStager" nocase ascii wide
                        $string35_koadic_offensive_tool_keyword = "bypassuac_compdefaults" nocase ascii wide
                        $string36_koadic_offensive_tool_keyword = "bypassuac_compmgmtlauncher" nocase ascii wide
                        $string37_koadic_offensive_tool_keyword = "bypassuac_eventvwr" nocase ascii wide
                        $string38_koadic_offensive_tool_keyword = "bypassuac_fodhelper" nocase ascii wide
                        $string39_koadic_offensive_tool_keyword = "bypassuac_sdclt" nocase ascii wide
                        $string40_koadic_offensive_tool_keyword = "bypassuac_slui" nocase ascii wide
                        $string41_koadic_offensive_tool_keyword = "bypassuac_systempropertiesadvanced" nocase ascii wide
                        $string42_koadic_offensive_tool_keyword = "bypassuac_wsreset" nocase ascii wide
                        $string43_koadic_offensive_tool_keyword = "cd koadic" nocase ascii wide
                        $string44_koadic_offensive_tool_keyword = "ClipboardImplant" nocase ascii wide
                        $string45_koadic_offensive_tool_keyword = "cmdshell " nocase ascii wide
                        $string46_koadic_offensive_tool_keyword = "comsvcs_lsass" nocase ascii wide
                        $string47_koadic_offensive_tool_keyword = "ComsvcsLSASS" nocase ascii wide
                        $string48_koadic_offensive_tool_keyword = "DotNet2JSImplant" nocase ascii wide
                        $string49_koadic_offensive_tool_keyword = "DownloadFileImplant" nocase ascii wide
                        $string50_koadic_offensive_tool_keyword = "EnableRDesktopImplant" nocase ascii wide
                        $string51_koadic_offensive_tool_keyword = /enum_domain_info\.py/ nocase ascii wide
                        $string52_koadic_offensive_tool_keyword = /enum_printers\.py/ nocase ascii wide
                        $string53_koadic_offensive_tool_keyword = /enum_shares\.py/ nocase ascii wide
                        $string54_koadic_offensive_tool_keyword = "ExcelReflectImplant" nocase ascii wide
                        $string55_koadic_offensive_tool_keyword = "ExecCmdImplant" nocase ascii wide
                        $string56_koadic_offensive_tool_keyword = "gather/user_hunter" nocase ascii wide
                        $string57_koadic_offensive_tool_keyword = "hashdump_sam" nocase ascii wide
                        $string58_koadic_offensive_tool_keyword = "HashDumpDCImplant" nocase ascii wide
                        $string59_koadic_offensive_tool_keyword = "HashDumpSAMImplant" nocase ascii wide
                        $string60_koadic_offensive_tool_keyword = "implant/elevate/" nocase ascii wide
                        $string61_koadic_offensive_tool_keyword = "implant/gather/" nocase ascii wide
                        $string62_koadic_offensive_tool_keyword = "implant/inject/" nocase ascii wide
                        $string63_koadic_offensive_tool_keyword = "implant/persist/" nocase ascii wide
                        $string64_koadic_offensive_tool_keyword = "implant/pivot/" nocase ascii wide
                        $string65_koadic_offensive_tool_keyword = "import Payload" nocase ascii wide
                        $string66_koadic_offensive_tool_keyword = "import Stager" nocase ascii wide
                        $string67_koadic_offensive_tool_keyword = "JScriptStager" nocase ascii wide
                        $string68_koadic_offensive_tool_keyword = /Koadic\.persist/ nocase ascii wide
                        $string69_koadic_offensive_tool_keyword = /koadic_load\./ nocase ascii wide
                        $string70_koadic_offensive_tool_keyword = /koadic_net\./ nocase ascii wide
                        $string71_koadic_offensive_tool_keyword = /koadic_process\./ nocase ascii wide
                        $string72_koadic_offensive_tool_keyword = /koadic_types\./ nocase ascii wide
                        $string73_koadic_offensive_tool_keyword = /koadic_util\./ nocase ascii wide
                        $string74_koadic_offensive_tool_keyword = "mimikatz_dotnet2js" nocase ascii wide
                        $string75_koadic_offensive_tool_keyword = "mimikatz_dynwrapx" nocase ascii wide
                        $string76_koadic_offensive_tool_keyword = "mimikatz_tashlib" nocase ascii wide
                        $string77_koadic_offensive_tool_keyword = /mimishim\./ nocase ascii wide
                        $string78_koadic_offensive_tool_keyword = "MSHTAStager" nocase ascii wide
                        $string79_koadic_offensive_tool_keyword = "offsecginger/koadic" nocase ascii wide
                        $string80_koadic_offensive_tool_keyword = /password_box\.py/ nocase ascii wide
                        $string81_koadic_offensive_tool_keyword = "PasswordBoxImplant" nocase ascii wide
                        $string82_koadic_offensive_tool_keyword = "PowerShellStager" nocase ascii wide
                        $string83_koadic_offensive_tool_keyword = "PsExecLiveImplant" nocase ascii wide
                        $string84_koadic_offensive_tool_keyword = /ReflectiveDLLInjection\./ nocase ascii wide
                        $string85_koadic_offensive_tool_keyword = "RegistryImplant" nocase ascii wide
                        $string86_koadic_offensive_tool_keyword = "RunDLL32JSStager" nocase ascii wide
                        $string87_koadic_offensive_tool_keyword = "ScanTCPImplant" nocase ascii wide
                        $string88_koadic_offensive_tool_keyword = "SchTasksImplant" nocase ascii wide
                        $string89_koadic_offensive_tool_keyword = /secretsdump\.py/ nocase ascii wide
                        $string90_koadic_offensive_tool_keyword = "seriously_nothing_shady_here" nocase ascii wide
                        $string91_koadic_offensive_tool_keyword = /set\s.{0,100}\svirus_scanner/ nocase ascii wide
                        $string92_koadic_offensive_tool_keyword = "set LFILE /" nocase ascii wide
                        $string93_koadic_offensive_tool_keyword = "set zombie " nocase ascii wide
                        $string94_koadic_offensive_tool_keyword = "shellcode_dotnet2js" nocase ascii wide
                        $string95_koadic_offensive_tool_keyword = "shellcode_dynwrapx" nocase ascii wide
                        $string96_koadic_offensive_tool_keyword = "stager/js/bitsadmin " nocase ascii wide
                        $string97_koadic_offensive_tool_keyword = "stager/js/disk" nocase ascii wide
                        $string98_koadic_offensive_tool_keyword = "stager/js/mshta" nocase ascii wide
                        $string99_koadic_offensive_tool_keyword = "stager/js/regsvr " nocase ascii wide
                        $string100_koadic_offensive_tool_keyword = "stager/js/rundll32_js " nocase ascii wide
                        $string101_koadic_offensive_tool_keyword = "stager/js/wmic " nocase ascii wide
                        $string102_koadic_offensive_tool_keyword = "SWbemServicesImplant" nocase ascii wide
                        $string103_koadic_offensive_tool_keyword = "UploadFileImplant" nocase ascii wide
                        $string104_koadic_offensive_tool_keyword = "use implant/" nocase ascii wide
                        $string105_koadic_offensive_tool_keyword = "use stager/" nocase ascii wide
                        $string106_koadic_offensive_tool_keyword = "UserHunterImplant" nocase ascii wide
                        $string107_koadic_offensive_tool_keyword = /windows_key\.py/ nocase ascii wide
                        $string108_koadic_offensive_tool_keyword = /wmic\/wmic\.cmd/ nocase ascii wide
                        $string109_koadic_offensive_tool_keyword = "WMICStager" nocase ascii wide
                        $string110_koadic_offensive_tool_keyword = "WMIPersistImplant" nocase ascii wide
                        $string111_koadic_offensive_tool_keyword = /zerosum0x0.{0,100}koadic/ nocase ascii wide
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