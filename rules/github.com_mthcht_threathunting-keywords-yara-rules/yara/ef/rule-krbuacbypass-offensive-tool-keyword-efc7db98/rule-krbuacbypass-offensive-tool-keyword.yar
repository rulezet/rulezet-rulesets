rule rule_KRBUACBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KRBUACBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KRBUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KRBUACBypass_offensive_tool_keyword = " KRBUACBypass" nocase ascii wide
                        $string2_KRBUACBypass_offensive_tool_keyword = /\.exe\sasktgs/ nocase ascii wide
                        $string3_KRBUACBypass_offensive_tool_keyword = /\.exe\skrbscm/ nocase ascii wide
                        $string4_KRBUACBypass_offensive_tool_keyword = "/KRBUACBypass" nocase ascii wide
                        $string5_KRBUACBypass_offensive_tool_keyword = /\/KRBUACBypass\.git/ nocase ascii wide
                        $string6_KRBUACBypass_offensive_tool_keyword = /\\KRBUACBypass/ nocase ascii wide
                        $string7_KRBUACBypass_offensive_tool_keyword = /\\S4U\.Exe/ nocase ascii wide
                        $string8_KRBUACBypass_offensive_tool_keyword = /\\SCMUACBypass\.cpp/ nocase ascii wide
                        $string9_KRBUACBypass_offensive_tool_keyword = "4291df077f27794311313530ae25457a0fbad23d402c789ed3336ace4b64150c" nocase ascii wide
                        $string10_KRBUACBypass_offensive_tool_keyword = "5d2e0f4adc5e3bb1f154c9f22eee2cf15e0bb2c5815653e3d97cb1e97c99c326" nocase ascii wide
                        $string11_KRBUACBypass_offensive_tool_keyword = "881D4D67-46DD-4F40-A813-C9D3C8BE0965" nocase ascii wide
                        $string12_KRBUACBypass_offensive_tool_keyword = /ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
                        $string13_KRBUACBypass_offensive_tool_keyword = "c3c993b043322cac38d24d751229883227de36b38e2c8c1e0fc1ca0ff6f2fd9a" nocase ascii wide
                        $string14_KRBUACBypass_offensive_tool_keyword = /Copyright\s\(c\)\s2023\swhoamianony\.top/ nocase ascii wide
                        $string15_KRBUACBypass_offensive_tool_keyword = "KRBUACBypass 1" nocase ascii wide
                        $string16_KRBUACBypass_offensive_tool_keyword = /KRBUACBypass\.csproj/ nocase ascii wide
                        $string17_KRBUACBypass_offensive_tool_keyword = /KRBUACBypass\.exe/ nocase ascii wide
                        $string18_KRBUACBypass_offensive_tool_keyword = /KRBUACBypass\.sln/ nocase ascii wide
                        $string19_KRBUACBypass_offensive_tool_keyword = "KRBUACBypass/tarball" nocase ascii wide
                        $string20_KRBUACBypass_offensive_tool_keyword = "KRBUACBypass/zipball" nocase ascii wide
                        $string21_KRBUACBypass_offensive_tool_keyword = /lib\/Bruteforcer\.cs/ nocase ascii wide
                        $string22_KRBUACBypass_offensive_tool_keyword = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string23_KRBUACBypass_offensive_tool_keyword = /Rubeus\/1\.0/ nocase ascii wide
                        $string24_KRBUACBypass_offensive_tool_keyword = "UACBypassedService" nocase ascii wide
                        $string25_KRBUACBypass_offensive_tool_keyword = "wh0amitz/KRBUACBypass" nocase ascii wide
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