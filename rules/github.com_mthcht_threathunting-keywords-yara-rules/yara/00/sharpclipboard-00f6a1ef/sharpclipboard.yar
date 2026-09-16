rule SharpClipboard
{
    meta:
        description = "Detection patterns for the tool 'SharpClipboard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpClipboard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpClipboard\.git/ nocase ascii wide
                        $string2 = /\\SharpClipboard\.csproj/ nocase ascii wide
                        $string3 = /\\SharpClipboard\.sln/ nocase ascii wide
                        $string4 = /\\SharpClipboard\\/ nocase ascii wide
                        $string5 = ">SharpClipboard<" nocase ascii wide
                        $string6 = "0556d3a1e4719382613891895582f8a392ccacfab6814bc9deafa9c99c86e553" nocase ascii wide
                        $string7 = "1ff4136cc59aec4f76d776abce00a592679490763f669a44eeead8f88c4a3c07" nocase ascii wide
                        $string8 = "803c76c8edc3cb686137d642d75fcedd54b89461c719504f2e5f8a3235c3f7c3" nocase ascii wide
                        $string9 = "97484211-4726-4129-86AA-AE01D17690BE" nocase ascii wide
                        $string10 = "981d1e5d88087f716ebb0cf8b39ffe7d3e44c36bc1e34452c8eaf2eaa56c05f9" nocase ascii wide
                        $string11 = /SharpClipboard\.exe/ nocase ascii wide
                        $string12 = /SharpClipboard\-master\.zip/ nocase ascii wide
                        $string13 = "slyd0g/SharpClipboard" nocase ascii wide
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