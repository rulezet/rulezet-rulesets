rule rule_SharpBlock_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpBlock' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBlock"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpBlock_offensive_tool_keyword = /\s\-d\s.{0,100}Active\sProtection\sDLL\sfor\sSylantStrike/ nocase ascii wide
                        $string2_SharpBlock_offensive_tool_keyword = " --disable-bypass-amsi" nocase ascii wide
                        $string3_SharpBlock_offensive_tool_keyword = " --disable-bypass-cmdline" nocase ascii wide
                        $string4_SharpBlock_offensive_tool_keyword = " --disable-bypass-etw" nocase ascii wide
                        $string5_SharpBlock_offensive_tool_keyword = "/SharpSploit/" nocase ascii wide
                        $string6_SharpBlock_offensive_tool_keyword = /\\\\\.\\pipe\\mimi/ nocase ascii wide
                        $string7_SharpBlock_offensive_tool_keyword = "execute-assembly SharpBlock" nocase ascii wide
                        $string8_SharpBlock_offensive_tool_keyword = "SharpBlock -" nocase ascii wide
                        $string9_SharpBlock_offensive_tool_keyword = /SharpBlock\.csproj/ nocase ascii wide
                        $string10_SharpBlock_offensive_tool_keyword = /SharpBlock\.exe/ nocase ascii wide
                        $string11_SharpBlock_offensive_tool_keyword = /SharpBlock\.sln/ nocase ascii wide
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