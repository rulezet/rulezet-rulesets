rule rule_Snaffler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Snaffler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Snaffler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Snaffler_offensive_tool_keyword = /\ssnaffler\.log/ nocase ascii wide
                        $string2_Snaffler_offensive_tool_keyword = /\/ShareFinder\.cs/ nocase ascii wide
                        $string3_Snaffler_offensive_tool_keyword = /\/SnaffCon\.cs/ nocase ascii wide
                        $string4_Snaffler_offensive_tool_keyword = "/SnaffCon/Snaffler" nocase ascii wide
                        $string5_Snaffler_offensive_tool_keyword = "/SnaffCore/" nocase ascii wide
                        $string6_Snaffler_offensive_tool_keyword = "/snafflertest/" nocase ascii wide
                        $string7_Snaffler_offensive_tool_keyword = /\/TreeWalker\.cs/ nocase ascii wide
                        $string8_Snaffler_offensive_tool_keyword = "SnaffCon/Snaffler" nocase ascii wide
                        $string9_Snaffler_offensive_tool_keyword = /SnaffCore\.csproj/ nocase ascii wide
                        $string10_Snaffler_offensive_tool_keyword = "SnaffCore/ActiveDirectory" nocase ascii wide
                        $string11_Snaffler_offensive_tool_keyword = "SnaffCore/Classifiers" nocase ascii wide
                        $string12_Snaffler_offensive_tool_keyword = "SnaffCore/Concurrency" nocase ascii wide
                        $string13_Snaffler_offensive_tool_keyword = "SnaffCore/Config" nocase ascii wide
                        $string14_Snaffler_offensive_tool_keyword = "SnaffCore/ShareFind" nocase ascii wide
                        $string15_Snaffler_offensive_tool_keyword = "SnaffCore/TreeWalk" nocase ascii wide
                        $string16_Snaffler_offensive_tool_keyword = /Snaffler\.csproj/ nocase ascii wide
                        $string17_Snaffler_offensive_tool_keyword = /snaffler\.exe/ nocase ascii wide
                        $string18_Snaffler_offensive_tool_keyword = /snaffler\.exe/ nocase ascii wide
                        $string19_Snaffler_offensive_tool_keyword = /snaffler\.log/ nocase ascii wide
                        $string20_Snaffler_offensive_tool_keyword = /Snaffler\.sln/ nocase ascii wide
                        $string21_Snaffler_offensive_tool_keyword = /Snaffler\.sln/ nocase ascii wide
                        $string22_Snaffler_offensive_tool_keyword = /SnafflerMessage\.cs/ nocase ascii wide
                        $string23_Snaffler_offensive_tool_keyword = /SnafflerMessageType\.cs/ nocase ascii wide
                        $string24_Snaffler_offensive_tool_keyword = /UltraSnaffCore\.csproj/ nocase ascii wide
                        $string25_Snaffler_offensive_tool_keyword = /UltraSnaffler\.sln/ nocase ascii wide
                        $string26_Snaffler_offensive_tool_keyword = /UltraSnaffler\.sln/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}