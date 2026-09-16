rule rule_rsocx_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rsocx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsocx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rsocx_offensive_tool_keyword = /\.\/rsocx\s\-/
                        $string2_rsocx_offensive_tool_keyword = /\/rsocx\-.{0,100}\-linux\-x86\-64\.zip/
                        $string3_rsocx_offensive_tool_keyword = /\/rsocx\-.{0,100}\-windows\-x86\-64\.zip/ nocase ascii wide
                        $string4_rsocx_offensive_tool_keyword = /\/rsocx\.exe/ nocase ascii wide
                        $string5_rsocx_offensive_tool_keyword = /\/rsocx\.git/ nocase ascii wide
                        $string6_rsocx_offensive_tool_keyword = "/rsocx/releases/download/" nocase ascii wide
                        $string7_rsocx_offensive_tool_keyword = /\\rsocx\.exe/ nocase ascii wide
                        $string8_rsocx_offensive_tool_keyword = "0908e1cfbd62968eea9ae9a3c772b6f134770c72b503affde0d551c8a55447c5" nocase ascii wide
                        $string9_rsocx_offensive_tool_keyword = "79ba1aa3b1b83aeb4db3fcf649b4acffce02a559a39b10905b4eb6676a646538" nocase ascii wide
                        $string10_rsocx_offensive_tool_keyword = "b23r0/rsocx" nocase ascii wide
                        $string11_rsocx_offensive_tool_keyword = "cargo install rsocx" nocase ascii wide
                        $string12_rsocx_offensive_tool_keyword = "cargo install rsocx" nocase ascii wide
                        $string13_rsocx_offensive_tool_keyword = "f3ba88e3c7410a48b8a15edccc2ededc4468d3babf5b9c07c4166cf58606f7d2" nocase ascii wide
                        $string14_rsocx_offensive_tool_keyword = "f81c31e5e8218f50da67495708f52079f59c0d96071f553086660fb47ff78e1c" nocase ascii wide
                        $string15_rsocx_offensive_tool_keyword = /rsocx\s\-l\s0\.0\.0\.0/ nocase ascii wide
                        $string16_rsocx_offensive_tool_keyword = /rsocx\s\-r\s.{0,100}\:/ nocase ascii wide
                        $string17_rsocx_offensive_tool_keyword = /rsocx\s\-t\s0\.0\.0\.0/ nocase ascii wide
                        $string18_rsocx_offensive_tool_keyword = /rsocx\.exe.{0,100}\s0\.0\.0\.0/ nocase ascii wide
                        $string19_rsocx_offensive_tool_keyword = /rsocx\.exe.{0,100}\s127\.0\.0\.1/ nocase ascii wide
                        $string20_rsocx_offensive_tool_keyword = /rsocx\-main\.zip/ nocase ascii wide
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