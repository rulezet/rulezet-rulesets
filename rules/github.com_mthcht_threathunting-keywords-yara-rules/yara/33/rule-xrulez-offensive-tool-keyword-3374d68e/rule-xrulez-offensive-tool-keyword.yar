rule rule_Xrulez_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Xrulez' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xrulez"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Xrulez_offensive_tool_keyword = /\sXRulez\.cpp/ nocase ascii wide
                        $string2_Xrulez_offensive_tool_keyword = /\/XRulez\sbinaries\.zip/ nocase ascii wide
                        $string3_Xrulez_offensive_tool_keyword = /\/XRulez\.exe/ nocase ascii wide
                        $string4_Xrulez_offensive_tool_keyword = /\/XRulez\.zip/ nocase ascii wide
                        $string5_Xrulez_offensive_tool_keyword = /\\2fac5c2a114c7896c33fb2b0a9f6443d\\/ nocase ascii wide
                        $string6_Xrulez_offensive_tool_keyword = /\\XRulez\.cpp/ nocase ascii wide
                        $string7_Xrulez_offensive_tool_keyword = /\\XRulez\.exe/ nocase ascii wide
                        $string8_Xrulez_offensive_tool_keyword = /\\XRulez\.sln/ nocase ascii wide
                        $string9_Xrulez_offensive_tool_keyword = /\\XRulez\.zip/ nocase ascii wide
                        $string10_Xrulez_offensive_tool_keyword = /\\XRulez\\Injector\\/ nocase ascii wide
                        $string11_Xrulez_offensive_tool_keyword = "070ccb075d1dada74121d232e657a9aeda429014f44da57491aa92fc5a279924" nocase ascii wide
                        $string12_Xrulez_offensive_tool_keyword = "14083A04-DD4B-4E7D-A16E-86947D3D6D74" nocase ascii wide
                        $string13_Xrulez_offensive_tool_keyword = "2661F29C-69F5-4010-9198-A418C061DD7C" nocase ascii wide
                        $string14_Xrulez_offensive_tool_keyword = "578a42cf90cf1bcc569f925d7909bbedd2756367906d2875a23cbc8bb1628577" nocase ascii wide
                        $string15_Xrulez_offensive_tool_keyword = "b90d7a75d6c85314b6232306f73ee17783f5b00882f264381ad3a9f4c2bedfa7" nocase ascii wide
                        $string16_Xrulez_offensive_tool_keyword = "b90d7a75d6c85314b6232306f73ee17783f5b00882f264381ad3a9f4c2bedfa7" nocase ascii wide
                        $string17_Xrulez_offensive_tool_keyword = /XRMod_h64e\.exe/ nocase ascii wide
                        $string18_Xrulez_offensive_tool_keyword = /Xrulez\s\+\sXRMod\.rwdi\.binaries\.zip/ nocase ascii wide
                        $string19_Xrulez_offensive_tool_keyword = /Xrulez\s\+\sXRMod\.x64\.binaries\.zip/ nocase ascii wide
                        $string20_Xrulez_offensive_tool_keyword = /Xrulez\s\+\sXRMod\.x86\.binaries\.zip/ nocase ascii wide
                        $string21_Xrulez_offensive_tool_keyword = /XRulez\sbinaries\.zip/ nocase ascii wide
                        $string22_Xrulez_offensive_tool_keyword = /XRulez\.\%2B\.XRMod\.rwdi\.binaries\.zip/ nocase ascii wide
                        $string23_Xrulez_offensive_tool_keyword = /XRulez\.\%2B\.XRMod\.x64\.binaries\.zip/ nocase ascii wide
                        $string24_Xrulez_offensive_tool_keyword = /XRulez\.\%2B\.XRMod\.x86\.binaries\.zip/ nocase ascii wide
                        $string25_Xrulez_offensive_tool_keyword = /XRulez\.\+\.XRMod\.x64\.binaries/ nocase ascii wide
                        $string26_Xrulez_offensive_tool_keyword = /XRulez\.exe\s/ nocase ascii wide
                        $string27_Xrulez_offensive_tool_keyword = /XRulez_h64d\.dll/ nocase ascii wide
                        $string28_Xrulez_offensive_tool_keyword = /XRulez_h64e\.exe/ nocase ascii wide
                        $string29_Xrulez_offensive_tool_keyword = /XRulez_rwdi86d\.dll/ nocase ascii wide
                        $string30_Xrulez_offensive_tool_keyword = /XRulezDll_rwdi64\.dll/ nocase ascii wide
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