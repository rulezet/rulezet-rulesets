rule rule_fuegoshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fuegoshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuegoshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fuegoshell_offensive_tool_keyword = /\sgenerate_bind_fuegoshell\.ps1/ nocase ascii wide
                        $string2_fuegoshell_offensive_tool_keyword = /\sgenerate_reverse_fuegoshell\.ps1/ nocase ascii wide
                        $string3_fuegoshell_offensive_tool_keyword = /\$myC2ipAdress/ nocase ascii wide
                        $string4_fuegoshell_offensive_tool_keyword = /\$myVictimIPAdress/ nocase ascii wide
                        $string5_fuegoshell_offensive_tool_keyword = /\/fuegoshell\.git/ nocase ascii wide
                        $string6_fuegoshell_offensive_tool_keyword = /\/generate_bind_fuegoshell\.ps1/ nocase ascii wide
                        $string7_fuegoshell_offensive_tool_keyword = /\/generate_reverse_fuegoshell\.ps1/ nocase ascii wide
                        $string8_fuegoshell_offensive_tool_keyword = /\[\+\]\sNew\sincoming\sshell\sfrom\s\:\s/ nocase ascii wide
                        $string9_fuegoshell_offensive_tool_keyword = /\\generate_bind_fuegoshell\.ps1/ nocase ascii wide
                        $string10_fuegoshell_offensive_tool_keyword = /\\generate_reverse_fuegoshell\.ps1/ nocase ascii wide
                        $string11_fuegoshell_offensive_tool_keyword = /\>\\fuego\-control/ nocase ascii wide
                        $string12_fuegoshell_offensive_tool_keyword = /\>\\fuego\-data/ nocase ascii wide
                        $string13_fuegoshell_offensive_tool_keyword = /\>\\fuegoshell/ nocase ascii wide
                        $string14_fuegoshell_offensive_tool_keyword = "5b64c12376f1ec1b876ede9b84f6883ee5f1ee5065e945dc2115c5e04c02aadf" nocase ascii wide
                        $string15_fuegoshell_offensive_tool_keyword = "6c6c37d26619bfe90a84e3e70c8dd45073488e120d239500bef10977f8523073" nocase ascii wide
                        $string16_fuegoshell_offensive_tool_keyword = "fuegoShell-bind>" nocase ascii wide
                        $string17_fuegoshell_offensive_tool_keyword = "Fuegoshell-client started" nocase ascii wide
                        $string18_fuegoshell_offensive_tool_keyword = "fuegoShell-reverse>" nocase ascii wide
                        $string19_fuegoshell_offensive_tool_keyword = "Fuegoshell-server started" nocase ascii wide
                        $string20_fuegoshell_offensive_tool_keyword = "Here are the oneliners for reverse shell using rpc named pipes" nocase ascii wide
                        $string21_fuegoshell_offensive_tool_keyword = /v1k1ngfr\.github\.io\/fuegoshell\// nocase ascii wide
                        $string22_fuegoshell_offensive_tool_keyword = "v1k1ngfr/fuegoshell" nocase ascii wide
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