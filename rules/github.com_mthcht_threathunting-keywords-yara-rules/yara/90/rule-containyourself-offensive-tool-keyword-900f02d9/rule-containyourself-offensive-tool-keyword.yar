rule rule_ContainYourself_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ContainYourself' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ContainYourself"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ContainYourself_offensive_tool_keyword = /\s\-\-copy\-file\s\-\-source\-file\s.{0,1000}\.docx\s\-\-target\-file\s.{0,1000}\.docx\s\-\-target\-volume\s/ nocase ascii wide
                        $string2_ContainYourself_offensive_tool_keyword = /\.exe\s\-\-override\-file\s\-\-source\-file\s.{0,1000}\.exe/ nocase ascii wide
                        $string3_ContainYourself_offensive_tool_keyword = /\.exe\s\-\-remove\-reparse\s\-\-source\-file\s.{0,1000}\.exe/ nocase ascii wide
                        $string4_ContainYourself_offensive_tool_keyword = /\.exe\s\-\-set\-reparse\soverride\s\-\-source\-file\s.{0,1000}\.exe\s\-\-target\-file\s/ nocase ascii wide
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

    condition:
        any of them
}