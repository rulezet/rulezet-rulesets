rule rule_BeRoot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BeRoot_offensive_tool_keyword = /\sbeRoot\.exe/
                        $string2_BeRoot_offensive_tool_keyword = /\sbeRoot\.py/
                        $string3_BeRoot_offensive_tool_keyword = "-------------- Get System Priv with WebClient --------------" nocase ascii wide
                        $string4_BeRoot_offensive_tool_keyword = /\/beRoot\.exe/
                        $string5_BeRoot_offensive_tool_keyword = /\/BeRoot\.git/
                        $string6_BeRoot_offensive_tool_keyword = /\/beRoot\.py/
                        $string7_BeRoot_offensive_tool_keyword = /\/beRoot\.zip/
                        $string8_BeRoot_offensive_tool_keyword = "/BeRoot/Linux/"
                        $string9_BeRoot_offensive_tool_keyword = /\/beroot\/modules\/.{0,100}\.py/ nocase ascii wide
                        $string10_BeRoot_offensive_tool_keyword = /\/gtfobins\.py/
                        $string11_BeRoot_offensive_tool_keyword = /\\beRoot\.exe/
                        $string12_BeRoot_offensive_tool_keyword = /\\beRoot\.zip/ nocase ascii wide
                        $string13_BeRoot_offensive_tool_keyword = /\\beroot\\modules\\.{0,100}\.py/ nocase ascii wide
                        $string14_BeRoot_offensive_tool_keyword = /\\DLL_Hijacking\./ nocase ascii wide
                        $string15_BeRoot_offensive_tool_keyword = "52B0FF57-7E0A-4CA9-84D4-58DFA2456BA5" nocase ascii wide
                        $string16_BeRoot_offensive_tool_keyword = "AlessandroZ/BeRoot" nocase ascii wide
                        $string17_BeRoot_offensive_tool_keyword = /beRoot\.exe\s\-/
                        $string18_BeRoot_offensive_tool_keyword = /beroot\.py\s\-/
                        $string19_BeRoot_offensive_tool_keyword = "BeRoot-master"
                        $string20_BeRoot_offensive_tool_keyword = /from\s\.modules\.exploit\simport\sExploit/ nocase ascii wide
                        $string21_BeRoot_offensive_tool_keyword = /from\s\.secretsdump\simport\sRemoteOperations/ nocase ascii wide
                        $string22_BeRoot_offensive_tool_keyword = /Getting\spermissions\sof\ssensitive\sfiles\./ nocase ascii wide
                        $string23_BeRoot_offensive_tool_keyword = "import check_currrent_user_privilege" nocase ascii wide
                        $string24_BeRoot_offensive_tool_keyword = "import check_sudoers_misconfigurations"
                        $string25_BeRoot_offensive_tool_keyword = "linux-exploit-suggester"
                        $string26_BeRoot_offensive_tool_keyword = /modules\.gtfobins\simport\sGTFOBins/ nocase ascii wide
                        $string27_BeRoot_offensive_tool_keyword = /modules\.interesting_files\simport\sInterestingFiles/ nocase ascii wide
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