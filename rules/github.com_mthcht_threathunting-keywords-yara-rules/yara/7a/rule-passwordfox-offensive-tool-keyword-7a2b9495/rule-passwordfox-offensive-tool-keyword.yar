rule rule_passwordfox_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'passwordfox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwordfox"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_passwordfox_offensive_tool_keyword = /\/utils\/passwordfox\.html/ nocase ascii wide
                        $string2_passwordfox_offensive_tool_keyword = ">PasswordFox<" nocase ascii wide
                        $string3_passwordfox_offensive_tool_keyword = ">Password-Recovery For Firefox<" nocase ascii wide
                        $string4_passwordfox_offensive_tool_keyword = "22c75c356f7e3a118f3fb98fe16c5c9232e3834e631ea1bb2af6a923f57b7b0b" nocase ascii wide
                        $string5_passwordfox_offensive_tool_keyword = "faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395" nocase ascii wide
                        $string6_passwordfox_offensive_tool_keyword = /passwordfox\.exe/ nocase ascii wide
                        $string7_passwordfox_offensive_tool_keyword = /passwordfox\.zip/ nocase ascii wide
                        $string8_passwordfox_offensive_tool_keyword = /passwordfox\-x64\.zip/ nocase ascii wide
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