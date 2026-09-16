rule rule_WDExtract_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WDExtract' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WDExtract"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WDExtract_offensive_tool_keyword = /\/wdextract\.cpp/ nocase ascii wide
                        $string2_WDExtract_offensive_tool_keyword = /\/wdextract\.cpp/ nocase ascii wide
                        $string3_WDExtract_offensive_tool_keyword = /\/WDExtract\.git/ nocase ascii wide
                        $string4_WDExtract_offensive_tool_keyword = /\/wdextract32\.exe/ nocase ascii wide
                        $string5_WDExtract_offensive_tool_keyword = /\/wdextract64\.exe/ nocase ascii wide
                        $string6_WDExtract_offensive_tool_keyword = /\\wdextract\.cpp/ nocase ascii wide
                        $string7_WDExtract_offensive_tool_keyword = /\\wdextract\.sln/ nocase ascii wide
                        $string8_WDExtract_offensive_tool_keyword = /\\wdextract\.vcxproj/ nocase ascii wide
                        $string9_WDExtract_offensive_tool_keyword = /\\wdextract32\.exe/ nocase ascii wide
                        $string10_WDExtract_offensive_tool_keyword = /\\wdextract64\.exe/ nocase ascii wide
                        $string11_WDExtract_offensive_tool_keyword = "04b99fb5cc1d91b1752fbcb2446db71083ab87af59dd9e0d940cc2ed5a65ef49" nocase ascii wide
                        $string12_WDExtract_offensive_tool_keyword = "086e302c10b4dc16180cdb87a84844a9b49b633ea6e965ad0db2319adb2af86e" nocase ascii wide
                        $string13_WDExtract_offensive_tool_keyword = "08AEC00F-42ED-4E62-AE8D-0BFCE30A3F57" nocase ascii wide
                        $string14_WDExtract_offensive_tool_keyword = "124e6ada27ffbe0ff97f51eb9d7caaf86b531bcff90ed5a075ff89b45b00cba5" nocase ascii wide
                        $string15_WDExtract_offensive_tool_keyword = "1f047faec08d9a35c304fb4a7cf13853589359a8f7cbfdd48c5d5807712dcf05" nocase ascii wide
                        $string16_WDExtract_offensive_tool_keyword = "1f047faec08d9a35c304fb4a7cf13853589359a8f7cbfdd48c5d5807712dcf05" nocase ascii wide
                        $string17_WDExtract_offensive_tool_keyword = "21582b3a68e8753322a1b1c7e550ae7fd305de4935de68fbde9f87570f484d00" nocase ascii wide
                        $string18_WDExtract_offensive_tool_keyword = "21582b3a68e8753322a1b1c7e550ae7fd305de4935de68fbde9f87570f484d00" nocase ascii wide
                        $string19_WDExtract_offensive_tool_keyword = "4d262988fe9d252191947ab780535d496ed24fa27668cf76c6cb9b6474a391c4" nocase ascii wide
                        $string20_WDExtract_offensive_tool_keyword = "4ddc82b4af931ab55f44d977bde81bfbc4151b5dcdccc03142831a301b5ec3c8" nocase ascii wide
                        $string21_WDExtract_offensive_tool_keyword = "6b95cd81ca4f309ac9f243ae73d2e8099634aaffead5b7b214bfcd14b6d604f6" nocase ascii wide
                        $string22_WDExtract_offensive_tool_keyword = "6e537702f0e29ddd6c134a1020396f42c30cd69da213d3fddfa645fc77c2449d" nocase ascii wide
                        $string23_WDExtract_offensive_tool_keyword = "77b78b6e16972c318fcbba39976858787cc31038f82952d2a94f844f5847a61e" nocase ascii wide
                        $string24_WDExtract_offensive_tool_keyword = "8304a65e6096bcf63f30592b8049d47883c3c755600796c60a36c4c492f7af37" nocase ascii wide
                        $string25_WDExtract_offensive_tool_keyword = "928097a924168caad66fead2633e4d44e4f585e0d33d05deb50b9c2d34cda246" nocase ascii wide
                        $string26_WDExtract_offensive_tool_keyword = "9c0087f31cd45fe4bfa0ca79b51df2c69d67c44f2fbb2223d7cf9ab8d971c360" nocase ascii wide
                        $string27_WDExtract_offensive_tool_keyword = "a6730ebb3e91961283f7a1cd95ace2a6d0d55e50531a64e57b03e61a8cf2d0e7" nocase ascii wide
                        $string28_WDExtract_offensive_tool_keyword = "beb285e40caf95bcc1552fc293194fa29275e3cdb9c62ef752b62257f6480aaf" nocase ascii wide
                        $string29_WDExtract_offensive_tool_keyword = /Bin\\bin32\\zlibwapi\.dll/ nocase ascii wide
                        $string30_WDExtract_offensive_tool_keyword = /Bin\\bin64\\zlibwapi\.dll/ nocase ascii wide
                        $string31_WDExtract_offensive_tool_keyword = "d091e408c0c5068b86bb69d17e91c5a7d6da46c0bd4101aa14f136246aed7f51" nocase ascii wide
                        $string32_WDExtract_offensive_tool_keyword = "d0ebb728926cce530040e046a8ea2f47e01158581cb0b5cccddc91007b421f6c" nocase ascii wide
                        $string33_WDExtract_offensive_tool_keyword = "d38210acb6d0568559041036abd033953c4080170e1ea9cf5d4d8499b54141b7" nocase ascii wide
                        $string34_WDExtract_offensive_tool_keyword = "dc3d98a8e8c0b0944291f9b462f552f174261982c4507f2de1ee9503353d10e9" nocase ascii wide
                        $string35_WDExtract_offensive_tool_keyword = "ExtractDataXML_BruteForce" nocase ascii wide
                        $string36_WDExtract_offensive_tool_keyword = "hfiref0x/WDExtract" nocase ascii wide
                        $string37_WDExtract_offensive_tool_keyword = /Source\\wdextract\\/ nocase ascii wide
                        $string38_WDExtract_offensive_tool_keyword = /Source\\wdextract\\zlib\\dll_x64\\zlibwapi\.dll/ nocase ascii wide
                        $string39_WDExtract_offensive_tool_keyword = /Source\\wdextract\\zlib\\dll_x86\\zlibwapi\.dll/ nocase ascii wide
                        $string40_WDExtract_offensive_tool_keyword = /Source\\wdextract\\zlib\\lib\\zlibwapi32\.lib/ nocase ascii wide
                        $string41_WDExtract_offensive_tool_keyword = /Source\\wdextract\\zlib\\lib\\zlibwapi64\.lib/ nocase ascii wide
                        $string42_WDExtract_offensive_tool_keyword = /wdextract\s.{0,100}\:\\.{0,100}\\.{0,100}\.vdm/ nocase ascii wide
                        $string43_WDExtract_offensive_tool_keyword = /wdextract\s.{0,100}\\mrt\.exe/ nocase ascii wide
                        $string44_WDExtract_offensive_tool_keyword = "WDExtract-master" nocase ascii wide
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