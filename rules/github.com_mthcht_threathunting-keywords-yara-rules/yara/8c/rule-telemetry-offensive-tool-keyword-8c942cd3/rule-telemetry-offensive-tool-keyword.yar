rule rule_Telemetry_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Telemetry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Telemetry"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Telemetry_offensive_tool_keyword = " Remotely download Trojan files to " nocase ascii wide
                        $string2_Telemetry_offensive_tool_keyword = /\/Telemetry\.git/ nocase ascii wide
                        $string3_Telemetry_offensive_tool_keyword = /\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\fun/ nocase ascii wide
                        $string4_Telemetry_offensive_tool_keyword = "2f00a05b-263d-4fcc-846b-da82bd684603" nocase ascii wide
                        $string5_Telemetry_offensive_tool_keyword = "58de3ab6935d1248e937e333e917586efb058e8b7d65ade38989543c806bd23e" nocase ascii wide
                        $string6_Telemetry_offensive_tool_keyword = "5f026c27-f8e6-4052-b231-8451c6a73838" nocase ascii wide
                        $string7_Telemetry_offensive_tool_keyword = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase ascii wide
                        $string8_Telemetry_offensive_tool_keyword = "6455d210924926d364ebf88ff053821ff2d603ea99b17d1dbb454a7d061992cc" nocase ascii wide
                        $string9_Telemetry_offensive_tool_keyword = "d7a308da069dcf3990f4cbfe57b8a1cc79c5f6b1259da795bba61592b8cf4b08" nocase ascii wide
                        $string10_Telemetry_offensive_tool_keyword = "Execute command without file backdoor" nocase ascii wide
                        $string11_Telemetry_offensive_tool_keyword = /https\:\/\/www\.trustedsec\.com\/blog\/abusing\-windows\-telemetry\-for\-persistence\// nocase ascii wide
                        $string12_Telemetry_offensive_tool_keyword = "Imanfeng/Telemetry" nocase ascii wide
                        $string13_Telemetry_offensive_tool_keyword = /TELEMETRY\.exe\sinstall\s/ nocase ascii wide
                        $string14_Telemetry_offensive_tool_keyword = /TELEMETRY\.exe\sinstall\s\/command\:/ nocase ascii wide
                        $string15_Telemetry_offensive_tool_keyword = /TELEMETRY\.exe\sinstall\s\/path\:/ nocase ascii wide
                        $string16_Telemetry_offensive_tool_keyword = /TELEMETRY\.exe\sinstall\s\/url\:/ nocase ascii wide
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