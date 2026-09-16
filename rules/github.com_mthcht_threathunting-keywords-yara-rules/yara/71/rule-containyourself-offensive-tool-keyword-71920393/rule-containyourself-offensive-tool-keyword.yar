rule rule_ContainYourself_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ContainYourself' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ContainYourself"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ContainYourself_offensive_tool_keyword = /\s\-\-copy\-file\s\-\-source\-file\s.{0,100}\.docx\s\-\-target\-file\s.{0,100}\.docx\s\-\-target\-volume\s/ nocase ascii wide
                        $string2_ContainYourself_offensive_tool_keyword = /\.exe\s\-\-override\-file\s\-\-source\-file\s.{0,100}\.exe/ nocase ascii wide
                        $string3_ContainYourself_offensive_tool_keyword = /\.exe\s\-\-remove\-reparse\s\-\-source\-file\s.{0,100}\.exe/ nocase ascii wide
                        $string4_ContainYourself_offensive_tool_keyword = /\.exe\s\-\-set\-reparse\soverride\s\-\-source\-file\s.{0,100}\.exe\s\-\-target\-file\s/ nocase ascii wide
                        $string5_ContainYourself_offensive_tool_keyword = /\/ContainYourself\.git/ nocase ascii wide
                        $string6_ContainYourself_offensive_tool_keyword = /\\WiperPoc\.cpp/ nocase ascii wide
                        $string7_ContainYourself_offensive_tool_keyword = "4F2AD0E0-8C4D-45CB-97DE-CE8D4177E7BF" nocase ascii wide
                        $string8_ContainYourself_offensive_tool_keyword = "79F54747-048D-4FD6-AEF4-7B098F923FD8" nocase ascii wide
                        $string9_ContainYourself_offensive_tool_keyword = "B5627919-4DFB-49C6-AC1B-C757F4B4A103" nocase ascii wide
                        $string10_ContainYourself_offensive_tool_keyword = /ContainYourself\.cpp/ nocase ascii wide
                        $string11_ContainYourself_offensive_tool_keyword = /ContainYourself\.exe/ nocase ascii wide
                        $string12_ContainYourself_offensive_tool_keyword = /ContainYourself\.sln/ nocase ascii wide
                        $string13_ContainYourself_offensive_tool_keyword = "ContainYourself-main" nocase ascii wide
                        $string14_ContainYourself_offensive_tool_keyword = /ContainYourselfPoc\.cpp/ nocase ascii wide
                        $string15_ContainYourself_offensive_tool_keyword = /ContainYourselfPoc\.exe/ nocase ascii wide
                        $string16_ContainYourself_offensive_tool_keyword = /ContainYourselfPoc\\/ nocase ascii wide
                        $string17_ContainYourself_offensive_tool_keyword = /ContainYourselfTempFile\.txt/ nocase ascii wide
                        $string18_ContainYourself_offensive_tool_keyword = "deepinstinct/ContainYourself" nocase ascii wide
                        $string19_ContainYourself_offensive_tool_keyword = "FA0DAF13-5058-4382-AE07-65E44AFB5592" nocase ascii wide
                        $string20_ContainYourself_offensive_tool_keyword = "Ransomware POC tool that encrypts a given directory" nocase ascii wide
                        $string21_ContainYourself_offensive_tool_keyword = /RansomwarePoc\.cpp/ nocase ascii wide
                        $string22_ContainYourself_offensive_tool_keyword = /RansomwarePoc\.exe/ nocase ascii wide
                        $string23_ContainYourself_offensive_tool_keyword = /RansomwarePoc\\RansomwarePoc/ nocase ascii wide
                        $string24_ContainYourself_offensive_tool_keyword = "Wiper POC tool that wipes a given directory" nocase ascii wide
                        $string25_ContainYourself_offensive_tool_keyword = /WiperPoc\.exe/ nocase ascii wide
                        $string26_ContainYourself_offensive_tool_keyword = /WiperPoc\\WiperPoc/ nocase ascii wide
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