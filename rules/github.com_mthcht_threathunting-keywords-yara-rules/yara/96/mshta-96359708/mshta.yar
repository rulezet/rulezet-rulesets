rule mshta
{
    meta:
        description = "Detection patterns for the tool 'mshta' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mshta"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /forfiles\.exe.{0,1000}\s\/p\s.{0,1000}\s\/m\s.{0,1000}\s\/c\s.{0,1000}powershell\s\.\smshta/ nocase ascii wide
                        $string2 = /mshta\s\\"C\:\\Users\\Public\\/ nocase ascii wide
                        $string3 = /mshta\shttp.{0,1000}\.hta/ nocase ascii wide
                        $string4 = /mshta\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string5 = /mshta\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
                        $string6 = /mshta\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,1000}\.sct.{0,1000}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
                        $string7 = /mshta\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide
                        $string8 = /mshta\.exe\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string9 = /mshta\.exe\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,1000}\.sct.{0,1000}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
                        $string10 = /mshta\.exe.{0,1000}\s\\"C\:\\Users\\Public\\/ nocase ascii wide
                        $string11 = /mshta\.exe.{0,1000}\shttp\:\/\// nocase ascii wide
                        $string12 = /mshta\.exe.{0,1000}\shttps\:\/\// nocase ascii wide
                        $string13 = /mshta\.exe.{0,1000}\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
                        $string14 = /mshta\.exe.{0,1000}\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide
                        $string15 = /mshta\.exe.{0,1000}I\sam\snot\sa\srobot\s\-\sreCAPTCHA\sVerification\sID\:\s/ nocase ascii wide

    condition:
        any of them
}