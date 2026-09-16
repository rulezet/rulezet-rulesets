rule rule_RedGuard_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RedGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedGuard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RedGuard_offensive_tool_keyword = /\.\/RedGuard/
                        $string2_RedGuard_offensive_tool_keyword = /\/RedGuard\.git/ nocase ascii wide
                        $string3_RedGuard_offensive_tool_keyword = /\/RedGuard\.go/ nocase ascii wide
                        $string4_RedGuard_offensive_tool_keyword = "/RedGuard_32" nocase ascii wide
                        $string5_RedGuard_offensive_tool_keyword = "/RedGuard_64" nocase ascii wide
                        $string6_RedGuard_offensive_tool_keyword = "/wikiZ/RedGuard" nocase ascii wide
                        $string7_RedGuard_offensive_tool_keyword = /\\RedGuard\s\-/ nocase ascii wide
                        $string8_RedGuard_offensive_tool_keyword = "866e5289337ab033f89bc57c5274c7ca" nocase ascii wide
                        $string9_RedGuard_offensive_tool_keyword = /OverrideLHOST\s360\.com/ nocase ascii wide
                        $string10_RedGuard_offensive_tool_keyword = /RedGuard\.log/ nocase ascii wide
                        $string11_RedGuard_offensive_tool_keyword = "RedGuard/core" nocase ascii wide
                        $string12_RedGuard_offensive_tool_keyword = /RedGuard_x64\.exe/ nocase ascii wide
                        $string13_RedGuard_offensive_tool_keyword = /RedGuard_x86\.exe/ nocase ascii wide
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