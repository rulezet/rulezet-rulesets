rule rule_DllNotificationInjection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DllNotificationInjection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllNotificationInjection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DllNotificationInjection_offensive_tool_keyword = /\/DllNotificationInjection\.git/ nocase ascii wide
                        $string2_DllNotificationInjection_offensive_tool_keyword = "0A1C2C46-33F7-4D4C-B8C6-1FC9B116A6DF" nocase ascii wide
                        $string3_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.cpp/ nocase ascii wide
                        $string4_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.exe/ nocase ascii wide
                        $string5_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.sln/ nocase ascii wide
                        $string6_DllNotificationInjection_offensive_tool_keyword = /DllNotificationInjection\.vcxproj/ nocase ascii wide
                        $string7_DllNotificationInjection_offensive_tool_keyword = "DllNotificationInjection-master" nocase ascii wide
                        $string8_DllNotificationInjection_offensive_tool_keyword = /ShellcodeTemplate\.x64\.bin/ nocase ascii wide
                        $string9_DllNotificationInjection_offensive_tool_keyword = "ShorSec/DllNotificationInjection" nocase ascii wide
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