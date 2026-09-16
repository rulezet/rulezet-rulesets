rule inceptor
{
    meta:
        description = "Detection patterns for the tool 'inceptor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "inceptor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sinceptor\..{0,100}dotnet/ nocase ascii wide
                        $string2 = /\sinceptor\.py/ nocase ascii wide
                        $string3 = /\sinceptor\.py/ nocase ascii wide
                        $string4 = /\sinceptor\.spec/ nocase ascii wide
                        $string5 = " --obfuscate " nocase ascii wide
                        $string6 = " --pinject " nocase ascii wide
                        $string7 = " --sign-domain " nocase ascii wide
                        $string8 = " --sign-steal " nocase ascii wide
                        $string9 = " -t donut " nocase ascii wide
                        $string10 = " -t pe2sh" nocase ascii wide
                        $string11 = " --transformer donut" nocase ascii wide
                        $string12 = " --transformer Loader" nocase ascii wide
                        $string13 = " --transformer pe2sh" nocase ascii wide
                        $string14 = " --transformer sRDI" nocase ascii wide
                        $string15 = /\.\/inceptor\.py/
                        $string16 = "/csharp/process_injection/" nocase ascii wide
                        $string17 = /\/inceptor\.git/ nocase ascii wide
                        $string18 = /\/inceptor\.git/ nocase ascii wide
                        $string19 = /\/Obfuscator\.py/ nocase ascii wide
                        $string20 = /\/Obfuscator\.py/ nocase ascii wide
                        $string21 = "/powershell/process_injection/" nocase ascii wide
                        $string22 = "/syscalls/syswhispers/" nocase ascii wide
                        $string23 = "/syscalls/syswhispersv2" nocase ascii wide
                        $string24 = "/syswhispersv2" nocase ascii wide
                        $string25 = /\\inceptor\.py/ nocase ascii wide
                        $string26 = /\\pe2sh\.exe/ nocase ascii wide
                        $string27 = /\]\sFetching\sLLVM\-Obfuscator\s\?/ nocase ascii wide
                        $string28 = /AesEncryptor\.py/ nocase ascii wide
                        $string29 = /AsStrongAsFuck\.exe/ nocase ascii wide
                        $string30 = /AsStrongAsFuck\.py/ nocase ascii wide
                        $string31 = /bypass\-classic\.dll/ nocase ascii wide
                        $string32 = /BYPASS\-DINVOKE.{0,100}\.dll/ nocase ascii wide
                        $string33 = /BYPASS\-DINVOKE\.dll/ nocase ascii wide
                        $string34 = /BYPASS\-DINVOKE_MANUAL_MAPPING\.dll/ nocase ascii wide
                        $string35 = /bypass\-powershell\.ps1/ nocase ascii wide
                        $string36 = "cd inceptor" nocase ascii wide
                        $string37 = /chameleon\.py\s/ nocase ascii wide
                        $string38 = /chunlie\.exe/ nocase ascii wide
                        $string39 = /cloc\.exe\s\-\-exclude\-dir/ nocase ascii wide
                        $string40 = /Confuser\.CLI\.exe/ nocase ascii wide
                        $string41 = /Confuser\.DynCipher\.dll/ nocase ascii wide
                        $string42 = /Confuser\.Renamer\.dll/ nocase ascii wide
                        $string43 = /DotNetArtifactGenerator\.py/ nocase ascii wide
                        $string44 = /frida\-trace\s\-x\sntdll\.dll\s\-i\s.{0,100}\s\-p\s/ nocase ascii wide
                        $string45 = /inceptor.{0,100}POWERSHELL/ nocase ascii wide
                        $string46 = /inceptor\.py\s/ nocase ascii wide
                        $string47 = "inceptor/obfuscators" nocase ascii wide
                        $string48 = /inceptor\-main\.zip/ nocase ascii wide
                        $string49 = "Invoke-AmsiBypass" nocase ascii wide
                        $string50 = "Invoke-IronCyclone" nocase ascii wide
                        $string51 = "Invoke-PsUACme" nocase ascii wide
                        $string52 = /Karmaleon\.py/ nocase ascii wide
                        $string53 = "klezVirus/inceptor" nocase ascii wide
                        $string54 = /mimikatz\.raw/ nocase ascii wide
                        $string55 = "msf-revhttps" nocase ascii wide
                        $string56 = /msf\-sgn\.raw/ nocase ascii wide
                        $string57 = /pe2sh\.exe/ nocase ascii wide
                        $string58 = /Pe2Shellcode\.py/ nocase ascii wide
                        $string59 = /PowerShellArtifactGenerator\.py/ nocase ascii wide
                        $string60 = /Rubeus\.bin/ nocase ascii wide
                        $string61 = /SharpConfigParser\.dll/ nocase ascii wide
                        $string62 = /SigThief\.py/ nocase ascii wide
                        $string63 = /steal\-cert\.py/ nocase ascii wide
                        $string64 = /syswhispers\.py/ nocase ascii wide
                        $string65 = /syswhispers\.py/ nocase ascii wide
                        $string66 = "syswhispersv2_x86" nocase ascii wide
                        $string67 = /ThreatCheck\.exe/ nocase ascii wide
                        $string68 = /winexec\.notepad\.raw/ nocase ascii wide
                        $string69 = /XorEncoder\.py/ nocase ascii wide
                        $string70 = /inceptor.{0,100}dotnet/ nocase ascii wide
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