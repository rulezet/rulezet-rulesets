rule rule_reverst_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reverst' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverst"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_reverst_offensive_tool_keyword = /\s\-\-http\-address\s127\.0\.0\.1\:8181/ nocase ascii wide
                        $string2_reverst_offensive_tool_keyword = /\s\-\-tunnel\-address\s127\.0\.0\.1\:7171/ nocase ascii wide
                        $string3_reverst_offensive_tool_keyword = /\.reverst\.tunnel\:/ nocase ascii wide
                        $string4_reverst_offensive_tool_keyword = "/cmd/reverst/"
                        $string5_reverst_offensive_tool_keyword = "/etc/reverst/"
                        $string6_reverst_offensive_tool_keyword = "/etc/reverst/"
                        $string7_reverst_offensive_tool_keyword = "/quic-go/quic-go/http3"
                        $string8_reverst_offensive_tool_keyword = /\/reverst\.git/ nocase ascii wide
                        $string9_reverst_offensive_tool_keyword = /\/reverst\.git/ nocase ascii wide
                        $string10_reverst_offensive_tool_keyword = "/usr/local/bin/reverst"
                        $string11_reverst_offensive_tool_keyword = "/usr/local/bin/reverst"
                        $string12_reverst_offensive_tool_keyword = "1d2c6cbd5fc288ffb92db49344a394eba6d3418df04bd6178007a33b8d82178e" nocase ascii wide
                        $string13_reverst_offensive_tool_keyword = "1d2c6cbd5fc288ffb92db49344a394eba6d3418df04bd6178007a33b8d82178e" nocase ascii wide
                        $string14_reverst_offensive_tool_keyword = "Bearer c29tZWludmFsaWQ6Y29tYmluYXRpb24=" nocase ascii wide
                        $string15_reverst_offensive_tool_keyword = "flipt-io/reverst" nocase ascii wide
                        $string16_reverst_offensive_tool_keyword = "flipt-io/reverst" nocase ascii wide
                        $string17_reverst_offensive_tool_keyword = /go\srun\s\.\/cmd\/reverst\//
                        $string18_reverst_offensive_tool_keyword = /go\.flipt\.io\/reverst\// nocase ascii wide
                        $string19_reverst_offensive_tool_keyword = /go\.flipt\.io\/reverst\// nocase ascii wide
                        $string20_reverst_offensive_tool_keyword = /reverst\s.{0,100}\-\-tunnel\-address\s/ nocase ascii wide
                        $string21_reverst_offensive_tool_keyword = "REVERST_CERTIFICATE_PATH" nocase ascii wide
                        $string22_reverst_offensive_tool_keyword = "REVERST_LOG" nocase ascii wide
                        $string23_reverst_offensive_tool_keyword = "REVERST_PRIVATE_KEY_PATH" nocase ascii wide
                        $string24_reverst_offensive_tool_keyword = "REVERST_SERVER_NAME" nocase ascii wide
                        $string25_reverst_offensive_tool_keyword = "REVERST_TUNNEL_ADDRESS" nocase ascii wide
                        $string26_reverst_offensive_tool_keyword = "REVERST_TUNNEL_GROUPS" nocase ascii wide
                        $string27_reverst_offensive_tool_keyword = "ZXZpbG1vcnR5Om11bHRpdmVyc2U=" nocase ascii wide
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