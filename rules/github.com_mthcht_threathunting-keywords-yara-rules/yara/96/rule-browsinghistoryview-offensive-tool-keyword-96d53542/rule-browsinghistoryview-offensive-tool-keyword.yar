rule rule_BrowsingHistoryView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BrowsingHistoryView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BrowsingHistoryView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BrowsingHistoryView_offensive_tool_keyword = /\.exe\s\s\/HistorySource\s1\s\/SaveDirect\s\/scomma\s/ nocase ascii wide
                        $string2_BrowsingHistoryView_offensive_tool_keyword = /\.exe\s\/HistorySource\s1\s\/LoadChrome\s1\s\/shtml\s/ nocase ascii wide
                        $string3_BrowsingHistoryView_offensive_tool_keyword = ">BrowsingHistoryView<" nocase ascii wide
                        $string4_BrowsingHistoryView_offensive_tool_keyword = "19a43d7ebc516f2344e6ffac66205d54cbde907e2eb1fb6171934d292524c5c7" nocase ascii wide
                        $string5_BrowsingHistoryView_offensive_tool_keyword = "1cc45acf429d705ee592af1c9e56ac25f5b5acbc27fe555db5007c8be9cc4c42" nocase ascii wide
                        $string6_BrowsingHistoryView_offensive_tool_keyword = "9f65528998b39f2e7239f89a56ded47ea865eea2d6b82b300cd5de7e62072cf0" nocase ascii wide
                        $string7_BrowsingHistoryView_offensive_tool_keyword = /BrowsingHistoryView\.cfg/ nocase ascii wide
                        $string8_BrowsingHistoryView_offensive_tool_keyword = /BrowsingHistoryView\.exe/ nocase ascii wide
                        $string9_BrowsingHistoryView_offensive_tool_keyword = /BROWSINGHISTORYVIEW\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string10_BrowsingHistoryView_offensive_tool_keyword = /browsinghistoryview\.zip/ nocase ascii wide
                        $string11_BrowsingHistoryView_offensive_tool_keyword = /browsinghistoryview\-x64\.zip/ nocase ascii wide
                        $string12_BrowsingHistoryView_offensive_tool_keyword = "c5bcfd00d0b8fda7c4b20cdc9649713d9f01dd12f61ce8ee9c45ec424a6bbdf2" nocase ascii wide
                        $string13_BrowsingHistoryView_offensive_tool_keyword = /nirsoft\.net\/utils\/browsing_history_view\.html/ nocase ascii wide
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