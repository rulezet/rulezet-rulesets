rule rule_WirelessKeyView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WirelessKeyView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WirelessKeyView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WirelessKeyView_offensive_tool_keyword = " /GetKeys WirelessKeyView" nocase ascii wide
                        $string2_WirelessKeyView_offensive_tool_keyword = ">Extracts wireless keys stored by Windows<" nocase ascii wide
                        $string3_WirelessKeyView_offensive_tool_keyword = ">Wireless Key View<" nocase ascii wide
                        $string4_WirelessKeyView_offensive_tool_keyword = "19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d" nocase ascii wide
                        $string5_WirelessKeyView_offensive_tool_keyword = "31ee7ee1add800239003806829b825cadc5b95797c11e33cf6b691571c1e2069" nocase ascii wide
                        $string6_WirelessKeyView_offensive_tool_keyword = "5d17e9dd54752bf9071caeccace27123897fe33de26db8c6f3e544abd11f7cb2" nocase ascii wide
                        $string7_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.exe/ nocase ascii wide
                        $string8_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.exe/ nocase ascii wide
                        $string9_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.zip/ nocase ascii wide
                        $string10_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.zip/ nocase ascii wide
                        $string11_WirelessKeyView_offensive_tool_keyword = /WirelessKeyView_x64\.exe/ nocase ascii wide
                        $string12_WirelessKeyView_offensive_tool_keyword = /WirelessKeyView_x64\.exe/ nocase ascii wide
                        $string13_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
                        $string14_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
                        $string15_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-x64\.zip/ nocase ascii wide
                        $string16_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-x64\.zip/ nocase ascii wide
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