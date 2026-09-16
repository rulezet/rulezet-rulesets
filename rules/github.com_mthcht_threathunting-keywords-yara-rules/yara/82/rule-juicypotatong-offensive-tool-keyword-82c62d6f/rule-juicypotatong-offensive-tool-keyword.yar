rule rule_JuicyPotatoNG_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'JuicyPotatoNG' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JuicyPotatoNG"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_JuicyPotatoNG_offensive_tool_keyword = " JuicyPotatoNG" nocase ascii wide
                        $string2_JuicyPotatoNG_offensive_tool_keyword = /\.exe\s\-l\s.{0,100}\s\-c\s\{B91D5831\-B1BD\-4608\-8198\-D72E155020F7\}/ nocase ascii wide
                        $string3_JuicyPotatoNG_offensive_tool_keyword = /\.exe\s\-l\s.{0,100}\s\-c\s\{F7FD3FD6\-9994\-452D\-8DA7\-9A8FD87AEEF4\}\s\-a/ nocase ascii wide
                        $string4_JuicyPotatoNG_offensive_tool_keyword = /\/JuicyPotatoNG\.git/ nocase ascii wide
                        $string5_JuicyPotatoNG_offensive_tool_keyword = /\[\-\]\sExploit\sfailed\!\s/ nocase ascii wide
                        $string6_JuicyPotatoNG_offensive_tool_keyword = /\[\+\]\sExploit\ssuccessful\!\s/ nocase ascii wide
                        $string7_JuicyPotatoNG_offensive_tool_keyword = /\\JuicyPotatoNG/ nocase ascii wide
                        $string8_JuicyPotatoNG_offensive_tool_keyword = /\]\sBruteforcing\s\%d\sCLSIDs/ nocase ascii wide
                        $string9_JuicyPotatoNG_offensive_tool_keyword = "261f880e-4bee-428d-9f64-c29292002c19" nocase ascii wide
                        $string10_JuicyPotatoNG_offensive_tool_keyword = "antonioCoco/JuicyPotatoNG" nocase ascii wide
                        $string11_JuicyPotatoNG_offensive_tool_keyword = /BruteforceCLSIDs\./ nocase ascii wide
                        $string12_JuicyPotatoNG_offensive_tool_keyword = "c5af796b44a3d3d09e184ef622ad002b8298696c2de139392fd35898f5073527" nocase ascii wide
                        $string13_JuicyPotatoNG_offensive_tool_keyword = "C73A4893-A5D1-44C8-900C-7B8850BBD2EC" nocase ascii wide
                        $string14_JuicyPotatoNG_offensive_tool_keyword = /JuicyPotatoNG\.cpp/ nocase ascii wide
                        $string15_JuicyPotatoNG_offensive_tool_keyword = /JuicyPotatoNG\.exe/ nocase ascii wide
                        $string16_JuicyPotatoNG_offensive_tool_keyword = /JuicyPotatoNG\.sln/ nocase ascii wide
                        $string17_JuicyPotatoNG_offensive_tool_keyword = /JuicyPotatoNG\.txt/ nocase ascii wide
                        $string18_JuicyPotatoNG_offensive_tool_keyword = /JuicyPotatoNG\.zip/ nocase ascii wide
                        $string19_JuicyPotatoNG_offensive_tool_keyword = "JuicyPotatoNG-main" nocase ascii wide
                        $string20_JuicyPotatoNG_offensive_tool_keyword = /PotatoTrigger\.cpp/ nocase ascii wide
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