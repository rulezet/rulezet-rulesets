rule rule_FourEye_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FourEye' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FourEye"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FourEye_offensive_tool_keyword = /\sBypassFramework\.py/ nocase ascii wide
                        $string2_FourEye_offensive_tool_keyword = /\sdarkexe\.py/ nocase ascii wide
                        $string3_FourEye_offensive_tool_keyword = /\sUUID_bypass\.py/ nocase ascii wide
                        $string4_FourEye_offensive_tool_keyword = /\/BypassFramework\.py/ nocase ascii wide
                        $string5_FourEye_offensive_tool_keyword = /\/darkexe\.py/ nocase ascii wide
                        $string6_FourEye_offensive_tool_keyword = /\/FourEye\.git/ nocase ascii wide
                        $string7_FourEye_offensive_tool_keyword = "/module/darkexe/" nocase ascii wide
                        $string8_FourEye_offensive_tool_keyword = /\/root\/shellcode\.c/
                        $string9_FourEye_offensive_tool_keyword = /\/root\/shellcode\.cpp/
                        $string10_FourEye_offensive_tool_keyword = /\/root\/shellcode\.exe/
                        $string11_FourEye_offensive_tool_keyword = /\/UUID_bypass\.py/ nocase ascii wide
                        $string12_FourEye_offensive_tool_keyword = /\\darkexe\.py/ nocase ascii wide
                        $string13_FourEye_offensive_tool_keyword = /\\UUID_bypass\.py/ nocase ascii wide
                        $string14_FourEye_offensive_tool_keyword = /FourEye\(shellcode_bypass/ nocase ascii wide
                        $string15_FourEye_offensive_tool_keyword = "FourEye-main" nocase ascii wide
                        $string16_FourEye_offensive_tool_keyword = "lengjibo/FourEye" nocase ascii wide
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