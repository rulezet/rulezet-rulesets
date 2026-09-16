rule rule_speedtest_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'speedtest' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "speedtest"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_speedtest_greyware_tool_keyword = /\/raw\/main\/speedtest\.exe/ nocase ascii wide
                        $string2_speedtest_greyware_tool_keyword = /\/raw\/master\/speedtest\.exe/ nocase ascii wide
                        $string3_speedtest_greyware_tool_keyword = /\\speedtest\.exe\s\-\-accept\-license/ nocase ascii wide
                        $string4_speedtest_greyware_tool_keyword = /\\speedtest\.exe\\"\s\-\-accept\-license/ nocase ascii wide
                        $string5_speedtest_greyware_tool_keyword = "dffc17b4b0f9c841d94802e2c9578758dbb52ca1ab967a506992c26aabecc43a" nocase ascii wide
                        $string6_speedtest_greyware_tool_keyword = /ProgramData\\speedtest\.exe/ nocase ascii wide
                        $string7_speedtest_greyware_tool_keyword = /ProgramData\\SpeedtestCLI/ nocase ascii wide
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