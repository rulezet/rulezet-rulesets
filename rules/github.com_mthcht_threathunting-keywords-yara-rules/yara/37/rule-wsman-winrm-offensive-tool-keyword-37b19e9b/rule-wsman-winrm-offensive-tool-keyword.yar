rule rule_WSMan_WinRM_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WSMan-WinRM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSMan-WinRM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WSMan_WinRM_offensive_tool_keyword = /\sSharpWSManWinRM\.vbs/ nocase ascii wide
                        $string2_WSMan_WinRM_offensive_tool_keyword = /\sWSManWinRM\.js\s/ nocase ascii wide
                        $string3_WSMan_WinRM_offensive_tool_keyword = /\sWSManWinRM\.ps1/ nocase ascii wide
                        $string4_WSMan_WinRM_offensive_tool_keyword = /\/CppWSManWinRM\.exe/ nocase ascii wide
                        $string5_WSMan_WinRM_offensive_tool_keyword = /\/SharpWSManWinRM\.vbs/ nocase ascii wide
                        $string6_WSMan_WinRM_offensive_tool_keyword = /\/WSMan\-WinRM\.git/ nocase ascii wide
                        $string7_WSMan_WinRM_offensive_tool_keyword = /\/WSManWinRM\.ps1/ nocase ascii wide
                        $string8_WSMan_WinRM_offensive_tool_keyword = /\\CppWSManWinRM\.exe/ nocase ascii wide
                        $string9_WSMan_WinRM_offensive_tool_keyword = /\\SharpWSManWinRM\.cs/ nocase ascii wide
                        $string10_WSMan_WinRM_offensive_tool_keyword = /\\SharpWSManWinRM\.vbs/ nocase ascii wide
                        $string11_WSMan_WinRM_offensive_tool_keyword = /\\WSManWinRM\.ps1/ nocase ascii wide
                        $string12_WSMan_WinRM_offensive_tool_keyword = "80ea8260d6148c716cf35ae8d8621a41b95cf4cd5857392698f1f21f62f2cb8e" nocase ascii wide
                        $string13_WSMan_WinRM_offensive_tool_keyword = "8478fe6c22a45230e79b057d13439a7ebc0e1a5054d14abbd3c8317add565a40" nocase ascii wide
                        $string14_WSMan_WinRM_offensive_tool_keyword = "8d8504a63c64c3cd8cd265846b04aef38128987c88bc9ca46144f85741e1fd33" nocase ascii wide
                        $string15_WSMan_WinRM_offensive_tool_keyword = "bohops/WSMan-WinRM" nocase ascii wide
                        $string16_WSMan_WinRM_offensive_tool_keyword = "ec002016f00ae6f232c1d5e166e5a01e48d3b25302e96a69d87fbf3fc8f05e50" nocase ascii wide
                        $string17_WSMan_WinRM_offensive_tool_keyword = "ed0a5937431223b74f639b0446fb35e05cd86cef2a752d5dd53d46555cee5e9b" nocase ascii wide
                        $string18_WSMan_WinRM_offensive_tool_keyword = /SharpWSManWinRM\.exe/ nocase ascii wide
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