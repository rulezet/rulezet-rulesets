rule rule_inceptor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'inceptor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "inceptor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_inceptor_offensive_tool_keyword = /\sinceptor\..{0,100}dotnet/ nocase ascii wide
                        $string2_inceptor_offensive_tool_keyword = /\sinceptor\.py/ nocase ascii wide
                        $string3_inceptor_offensive_tool_keyword = /\sinceptor\.py/ nocase ascii wide
                        $string4_inceptor_offensive_tool_keyword = /\sinceptor\.spec/ nocase ascii wide
                        $string5_inceptor_offensive_tool_keyword = " --obfuscate " nocase ascii wide
                        $string6_inceptor_offensive_tool_keyword = " --pinject " nocase ascii wide
                        $string7_inceptor_offensive_tool_keyword = " --sign-domain " nocase ascii wide
                        $string8_inceptor_offensive_tool_keyword = " --sign-steal " nocase ascii wide
                        $string9_inceptor_offensive_tool_keyword = " -t donut " nocase ascii wide
                        $string10_inceptor_offensive_tool_keyword = " -t pe2sh" nocase ascii wide
                        $string11_inceptor_offensive_tool_keyword = " --transformer donut" nocase ascii wide
                        $string12_inceptor_offensive_tool_keyword = " --transformer Loader" nocase ascii wide
                        $string13_inceptor_offensive_tool_keyword = " --transformer pe2sh" nocase ascii wide
                        $string14_inceptor_offensive_tool_keyword = " --transformer sRDI" nocase ascii wide
                        $string15_inceptor_offensive_tool_keyword = /\.\/inceptor\.py/
                        $string16_inceptor_offensive_tool_keyword = "/csharp/process_injection/" nocase ascii wide
                        $string17_inceptor_offensive_tool_keyword = /\/inceptor\.git/ nocase ascii wide
                        $string18_inceptor_offensive_tool_keyword = /\/inceptor\.git/ nocase ascii wide
                        $string19_inceptor_offensive_tool_keyword = /\/Obfuscator\.py/ nocase ascii wide
                        $string20_inceptor_offensive_tool_keyword = /\/Obfuscator\.py/ nocase ascii wide
                        $string21_inceptor_offensive_tool_keyword = "/powershell/process_injection/" nocase ascii wide
                        $string22_inceptor_offensive_tool_keyword = "/syscalls/syswhispers/" nocase ascii wide
                        $string23_inceptor_offensive_tool_keyword = "/syscalls/syswhispersv2" nocase ascii wide
                        $string24_inceptor_offensive_tool_keyword = "/syswhispersv2" nocase ascii wide
                        $string25_inceptor_offensive_tool_keyword = /\\inceptor\.py/ nocase ascii wide
                        $string26_inceptor_offensive_tool_keyword = /\\pe2sh\.exe/ nocase ascii wide
                        $string27_inceptor_offensive_tool_keyword = /\]\sFetching\sLLVM\-Obfuscator\s\?/ nocase ascii wide
                        $string28_inceptor_offensive_tool_keyword = /AesEncryptor\.py/ nocase ascii wide
                        $string29_inceptor_offensive_tool_keyword = /AsStrongAsFuck\.exe/ nocase ascii wide
                        $string30_inceptor_offensive_tool_keyword = /AsStrongAsFuck\.py/ nocase ascii wide
                        $string31_inceptor_offensive_tool_keyword = /bypass\-classic\.dll/ nocase ascii wide
                        $string32_inceptor_offensive_tool_keyword = /BYPASS\-DINVOKE.{0,100}\.dll/ nocase ascii wide
                        $string33_inceptor_offensive_tool_keyword = /BYPASS\-DINVOKE\.dll/ nocase ascii wide
                        $string34_inceptor_offensive_tool_keyword = /BYPASS\-DINVOKE_MANUAL_MAPPING\.dll/ nocase ascii wide
                        $string35_inceptor_offensive_tool_keyword = /bypass\-powershell\.ps1/ nocase ascii wide
                        $string36_inceptor_offensive_tool_keyword = "cd inceptor" nocase ascii wide
                        $string37_inceptor_offensive_tool_keyword = /chameleon\.py\s/ nocase ascii wide
                        $string38_inceptor_offensive_tool_keyword = /chunlie\.exe/ nocase ascii wide
                        $string39_inceptor_offensive_tool_keyword = /cloc\.exe\s\-\-exclude\-dir/ nocase ascii wide
                        $string40_inceptor_offensive_tool_keyword = /Confuser\.CLI\.exe/ nocase ascii wide
                        $string41_inceptor_offensive_tool_keyword = /Confuser\.DynCipher\.dll/ nocase ascii wide
                        $string42_inceptor_offensive_tool_keyword = /Confuser\.Renamer\.dll/ nocase ascii wide
                        $string43_inceptor_offensive_tool_keyword = /DotNetArtifactGenerator\.py/ nocase ascii wide
                        $string44_inceptor_offensive_tool_keyword = /frida\-trace\s\-x\sntdll\.dll\s\-i\s.{0,100}\s\-p\s/ nocase ascii wide
                        $string45_inceptor_offensive_tool_keyword = /inceptor.{0,100}POWERSHELL/ nocase ascii wide
                        $string46_inceptor_offensive_tool_keyword = /inceptor\.py\s/ nocase ascii wide
                        $string47_inceptor_offensive_tool_keyword = "inceptor/obfuscators" nocase ascii wide
                        $string48_inceptor_offensive_tool_keyword = /inceptor\-main\.zip/ nocase ascii wide
                        $string49_inceptor_offensive_tool_keyword = "Invoke-AmsiBypass" nocase ascii wide
                        $string50_inceptor_offensive_tool_keyword = "Invoke-IronCyclone" nocase ascii wide
                        $string51_inceptor_offensive_tool_keyword = "Invoke-PsUACme" nocase ascii wide
                        $string52_inceptor_offensive_tool_keyword = /Karmaleon\.py/ nocase ascii wide
                        $string53_inceptor_offensive_tool_keyword = "klezVirus/inceptor" nocase ascii wide
                        $string54_inceptor_offensive_tool_keyword = /mimikatz\.raw/ nocase ascii wide
                        $string55_inceptor_offensive_tool_keyword = "msf-revhttps" nocase ascii wide
                        $string56_inceptor_offensive_tool_keyword = /msf\-sgn\.raw/ nocase ascii wide
                        $string57_inceptor_offensive_tool_keyword = /pe2sh\.exe/ nocase ascii wide
                        $string58_inceptor_offensive_tool_keyword = /Pe2Shellcode\.py/ nocase ascii wide
                        $string59_inceptor_offensive_tool_keyword = /PowerShellArtifactGenerator\.py/ nocase ascii wide
                        $string60_inceptor_offensive_tool_keyword = /Rubeus\.bin/ nocase ascii wide
                        $string61_inceptor_offensive_tool_keyword = /SharpConfigParser\.dll/ nocase ascii wide
                        $string62_inceptor_offensive_tool_keyword = /SigThief\.py/ nocase ascii wide
                        $string63_inceptor_offensive_tool_keyword = /steal\-cert\.py/ nocase ascii wide
                        $string64_inceptor_offensive_tool_keyword = /syswhispers\.py/ nocase ascii wide
                        $string65_inceptor_offensive_tool_keyword = /syswhispers\.py/ nocase ascii wide
                        $string66_inceptor_offensive_tool_keyword = "syswhispersv2_x86" nocase ascii wide
                        $string67_inceptor_offensive_tool_keyword = /ThreatCheck\.exe/ nocase ascii wide
                        $string68_inceptor_offensive_tool_keyword = /winexec\.notepad\.raw/ nocase ascii wide
                        $string69_inceptor_offensive_tool_keyword = /XorEncoder\.py/ nocase ascii wide
                        $string70_inceptor_offensive_tool_keyword = /inceptor.{0,100}dotnet/ nocase ascii wide
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