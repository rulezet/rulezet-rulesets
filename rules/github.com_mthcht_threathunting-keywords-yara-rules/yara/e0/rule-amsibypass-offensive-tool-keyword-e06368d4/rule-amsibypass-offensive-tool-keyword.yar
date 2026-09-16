rule rule_AmsiBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AmsiBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmsiBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AmsiBypass_offensive_tool_keyword = /\/AmsiBypass\./ nocase ascii wide
                        $string2_AmsiBypass_offensive_tool_keyword = /\/Amsi\-Bypass\-Powershell\.git/ nocase ascii wide
                        $string3_AmsiBypass_offensive_tool_keyword = "/opt/Projects/AmsiBypass/"
                        $string4_AmsiBypass_offensive_tool_keyword = /\\AmsiBypass\./ nocase ascii wide
                        $string5_AmsiBypass_offensive_tool_keyword = "132ab5d9aa388ae3a6575a01fadeb7fa7f77aac1150fc54bc1d20ae32b58ddc5" nocase ascii wide
                        $string6_AmsiBypass_offensive_tool_keyword = "Invoke-PsUACme -Method " nocase ascii wide
                        $string7_AmsiBypass_offensive_tool_keyword = "Modified-Amsi-ScanBuffer-Patch" nocase ascii wide
                        $string8_AmsiBypass_offensive_tool_keyword = "Nishang-all-in-one" nocase ascii wide
                        $string9_AmsiBypass_offensive_tool_keyword = "Patching-AMSI-AmsiScanBuffer-by-rasta-mouse" nocase ascii wide
                        $string10_AmsiBypass_offensive_tool_keyword = "S3cur3Th1sSh1t/Amsi-Bypass-Powershell" nocase ascii wide
                        $string11_AmsiBypass_offensive_tool_keyword = /\'System\.Ma\'\+\'nag\'\+\'eme\'\+\'nt\.Autom\'\+\'ation\.A\'\+\'ms\'\+\'iU\'\+\'ti\'\+\'ls\'/ nocase ascii wide
                        $string12_AmsiBypass_offensive_tool_keyword = "Tztufn/Nbobhfnfou/Bvupnbujpo/BntjVujmt" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}