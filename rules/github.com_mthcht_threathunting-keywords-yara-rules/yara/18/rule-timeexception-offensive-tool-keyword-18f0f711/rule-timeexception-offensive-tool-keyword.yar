rule rule_TimeException_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TimeException' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TimeException"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TimeException_offensive_tool_keyword = /\.exe\s\-\-sample\-size\s1000\s\-\-mode\s0\s\-\-targets\sdirs\.txt/ nocase ascii wide
                        $string2_TimeException_offensive_tool_keyword = /\.exe\s\-\-sample\-size\s1000\s\-\-mode\s1\s\-\-targets\sexts\.txt/ nocase ascii wide
                        $string3_TimeException_offensive_tool_keyword = /\/TimeException\.exe/ nocase ascii wide
                        $string4_TimeException_offensive_tool_keyword = /\/TimeException\.git/ nocase ascii wide
                        $string5_TimeException_offensive_tool_keyword = /\\TimeException\.cpp/ nocase ascii wide
                        $string6_TimeException_offensive_tool_keyword = /\\TimeException\.exe/ nocase ascii wide
                        $string7_TimeException_offensive_tool_keyword = /\\TimeException\-main/ nocase ascii wide
                        $string8_TimeException_offensive_tool_keyword = "30fb8b27a7636a8922aff3018b2b612bf224a17bf7a9c9f2f2a01d4f7754c522" nocase ascii wide
                        $string9_TimeException_offensive_tool_keyword = "bananabr/TimeException" nocase ascii wide
                        $string10_TimeException_offensive_tool_keyword = "c6a8d755e4764335fa9c5313c6ba641ac9a0228648065667f7d535457dbf0ceb" nocase ascii wide
                        $string11_TimeException_offensive_tool_keyword = "e69f0324-3afb-485e-92c7-cb097ea47caf" nocase ascii wide
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