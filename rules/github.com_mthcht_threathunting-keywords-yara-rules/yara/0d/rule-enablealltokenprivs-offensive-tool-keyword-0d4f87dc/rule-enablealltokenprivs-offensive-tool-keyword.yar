rule rule_EnableAllTokenPrivs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EnableAllTokenPrivs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EnableAllTokenPrivs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EnableAllTokenPrivs_offensive_tool_keyword = /\sEnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string2_EnableAllTokenPrivs_offensive_tool_keyword = /\sEnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string3_EnableAllTokenPrivs_offensive_tool_keyword = /\s\-\-pid\s.{0,100}\s\-\-disable\s\-\-privilege\sSeDebugPrivilege/ nocase ascii wide
                        $string4_EnableAllTokenPrivs_offensive_tool_keyword = /\/EnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string5_EnableAllTokenPrivs_offensive_tool_keyword = /\/EnableAllTokenPrivs\.git/ nocase ascii wide
                        $string6_EnableAllTokenPrivs_offensive_tool_keyword = /\/EnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string7_EnableAllTokenPrivs_offensive_tool_keyword = /\\EnableAllTokenPrivs\.cs/ nocase ascii wide
                        $string8_EnableAllTokenPrivs_offensive_tool_keyword = /\\EnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string9_EnableAllTokenPrivs_offensive_tool_keyword = /\\EnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string10_EnableAllTokenPrivs_offensive_tool_keyword = "3C8AA457-3659-4CDD-A685-66F7ED10DC4F" nocase ascii wide
                        $string11_EnableAllTokenPrivs_offensive_tool_keyword = "b7d464d0d52a2c35760aa7cf90a90e1ea3513a8827b175aba5099a90dee416f9" nocase ascii wide
                        $string12_EnableAllTokenPrivs_offensive_tool_keyword = "d1d4d168eeedd0867537ba4cf5befd1ea7adab62843d21088e6c51e27dec34c5" nocase ascii wide
                        $string13_EnableAllTokenPrivs_offensive_tool_keyword = /EnableAllTokenPrivs\.exe\.log/ nocase ascii wide
                        $string14_EnableAllTokenPrivs_offensive_tool_keyword = /execute\-assembly\s\-c\sEnableAllTokenPrivs\.EnableAllTokenPrivs\s/ nocase ascii wide
                        $string15_EnableAllTokenPrivs_offensive_tool_keyword = "xvt-void/EnableAllTokenPrivs" nocase ascii wide
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