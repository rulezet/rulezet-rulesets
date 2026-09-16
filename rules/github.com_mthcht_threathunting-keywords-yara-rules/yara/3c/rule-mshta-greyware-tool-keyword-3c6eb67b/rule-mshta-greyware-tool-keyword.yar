rule rule_mshta_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mshta' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mshta"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_mshta_greyware_tool_keyword = /forfiles\.exe.{0,1000}\s\/p\s.{0,1000}\s\/m\s.{0,1000}\s\/c\s.{0,1000}powershell\s\.\smshta/ nocase ascii wide
                        $string2_mshta_greyware_tool_keyword = /mshta\s\\"C\:\\Users\\Public\\/ nocase ascii wide
                        $string3_mshta_greyware_tool_keyword = /mshta\shttp.{0,1000}\.hta/ nocase ascii wide
                        $string4_mshta_greyware_tool_keyword = /mshta\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string5_mshta_greyware_tool_keyword = /mshta\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
                        $string6_mshta_greyware_tool_keyword = /mshta\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,1000}\.sct.{0,1000}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
                        $string7_mshta_greyware_tool_keyword = /mshta\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide
                        $string8_mshta_greyware_tool_keyword = /mshta\.exe\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string9_mshta_greyware_tool_keyword = /mshta\.exe\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,1000}\.sct.{0,1000}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
                        $string10_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\s\\"C\:\\Users\\Public\\/ nocase ascii wide
                        $string11_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\shttp\:\/\// nocase ascii wide
                        $string12_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\shttps\:\/\// nocase ascii wide
                        $string13_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
                        $string14_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide
                        $string15_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}I\sam\snot\sa\srobot\s\-\sreCAPTCHA\sVerification\sID\:\s/ nocase ascii wide

    condition:
        any of them
}