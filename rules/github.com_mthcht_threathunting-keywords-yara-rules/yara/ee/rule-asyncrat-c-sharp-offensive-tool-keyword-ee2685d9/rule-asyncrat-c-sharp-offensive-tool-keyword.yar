rule rule_AsyncRAT_C_Sharp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AsyncRAT-C-Sharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AsyncRAT-C-Sharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AsyncRAT_C_Sharp_offensive_tool_keyword = "/AsyncRAT-C%23" nocase ascii wide
                        $string2_AsyncRAT_C_Sharp_offensive_tool_keyword = "/AsyncRAT-C-Sharp" nocase ascii wide
                        $string3_AsyncRAT_C_Sharp_offensive_tool_keyword = /\\AsyncRAT\\/ nocase ascii wide
                        $string4_AsyncRAT_C_Sharp_offensive_tool_keyword = /\\Plugins\\RemoteCamera\.dll/ nocase ascii wide
                        $string5_AsyncRAT_C_Sharp_offensive_tool_keyword = /\\Plugins\\RemoteDesktop\.dll/ nocase ascii wide
                        $string6_AsyncRAT_C_Sharp_offensive_tool_keyword = "0DE8DA5D-061D-4649-8A56-48729CF1F789" nocase ascii wide
                        $string7_AsyncRAT_C_Sharp_offensive_tool_keyword = "619B7612-DFEA-442A-A927-D997F99C497B" nocase ascii wide
                        $string8_AsyncRAT_C_Sharp_offensive_tool_keyword = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase ascii wide
                        $string9_AsyncRAT_C_Sharp_offensive_tool_keyword = "AsyncRAT  Simple RAT" nocase ascii wide
                        $string10_AsyncRAT_C_Sharp_offensive_tool_keyword = "AsyncRAT Server" nocase ascii wide
                        $string11_AsyncRAT_C_Sharp_offensive_tool_keyword = /AsyncRAT\.exe/ nocase ascii wide
                        $string12_AsyncRAT_C_Sharp_offensive_tool_keyword = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
                        $string13_AsyncRAT_C_Sharp_offensive_tool_keyword = "Hp6kvaq9BCyI" nocase ascii wide
                        $string14_AsyncRAT_C_Sharp_offensive_tool_keyword = /User\-Agent.{0,100}NIKMOK/ nocase ascii wide
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