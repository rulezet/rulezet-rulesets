rule rule_crossc2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crossc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crossc2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_crossc2_offensive_tool_keyword = "/CrossC2-test" nocase ascii wide
                        $string2_crossc2_offensive_tool_keyword = "/mimipenguin/" nocase ascii wide
                        $string3_crossc2_offensive_tool_keyword = /\/tmp\/c2\-rebind\.so/
                        $string4_crossc2_offensive_tool_keyword = /c2profile\.profile/ nocase ascii wide
                        $string5_crossc2_offensive_tool_keyword = "cc2_keystrokes" nocase ascii wide
                        $string6_crossc2_offensive_tool_keyword = "cc2_portscan" nocase ascii wide
                        $string7_crossc2_offensive_tool_keyword = /CCHOST\=127\.0\.0\.1.{0,100}\/tmp\/c2/ nocase ascii wide
                        $string8_crossc2_offensive_tool_keyword = "crossc2 dyn load" nocase ascii wide
                        $string9_crossc2_offensive_tool_keyword = "CrossC2 framework" nocase ascii wide
                        $string10_crossc2_offensive_tool_keyword = /CrossC2\.cna/ nocase ascii wide
                        $string11_crossc2_offensive_tool_keyword = /CrossC2\.git/ nocase ascii wide
                        $string12_crossc2_offensive_tool_keyword = /CrossC2\.Linux/
                        $string13_crossc2_offensive_tool_keyword = /CrossC2\.MacOS/ nocase ascii wide
                        $string14_crossc2_offensive_tool_keyword = /CrossC2\.Win/ nocase ascii wide
                        $string15_crossc2_offensive_tool_keyword = "CrossC2_dev_" nocase ascii wide
                        $string16_crossc2_offensive_tool_keyword = "CrossC2-cs" nocase ascii wide
                        $string17_crossc2_offensive_tool_keyword = "CrossC2-GithubBot" nocase ascii wide
                        $string18_crossc2_offensive_tool_keyword = "CrossC2Kit" nocase ascii wide
                        $string19_crossc2_offensive_tool_keyword = "genCrossC2 " nocase ascii wide
                        $string20_crossc2_offensive_tool_keyword = /genCrossC2\.Win\.exe/ nocase ascii wide
                        $string21_crossc2_offensive_tool_keyword = "gloxec/CrossC2" nocase ascii wide
                        $string22_crossc2_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/CrossC2/ nocase ascii wide
                        $string23_crossc2_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\:443\/aaaaaaaaa/ nocase ascii wide
                        $string24_crossc2_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\:443\/bbbbbbbbb/ nocase ascii wide
                        $string25_crossc2_offensive_tool_keyword = /mimipenguin\./ nocase ascii wide
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