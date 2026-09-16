rule rule_advanced_ip_scanner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'advanced-ip-scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced-ip-scanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_advanced_ip_scanner_greyware_tool_keyword = /\.exe\s\/s\:ip_ranges\.txt\s\/f\:scan_results\.txt/ nocase ascii wide
                        $string2_advanced_ip_scanner_greyware_tool_keyword = /\\Advanced\sIP\sScanner\.lnk/ nocase ascii wide
                        $string3_advanced_ip_scanner_greyware_tool_keyword = /\\advanced_ip_scanner/ nocase ascii wide
                        $string4_advanced_ip_scanner_greyware_tool_keyword = /\\Local\\Temp\\Advanced\sIP\sScanner\s2\\/ nocase ascii wide
                        $string5_advanced_ip_scanner_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Advanced\sIP\sScanner\\/ nocase ascii wide
                        $string6_advanced_ip_scanner_greyware_tool_keyword = /\\Programs\\Advanced\sIP\sScanner\sPortable\\/ nocase ascii wide
                        $string7_advanced_ip_scanner_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Advanced\sIP\sScanner\sv2/ nocase ascii wide
                        $string8_advanced_ip_scanner_greyware_tool_keyword = ">Advanced IP Scanner Setup<" nocase ascii wide
                        $string9_advanced_ip_scanner_greyware_tool_keyword = ">Advanced IP Scanner<" nocase ascii wide
                        $string10_advanced_ip_scanner_greyware_tool_keyword = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b" nocase ascii wide
                        $string11_advanced_ip_scanner_greyware_tool_keyword = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b" nocase ascii wide
                        $string12_advanced_ip_scanner_greyware_tool_keyword = "Advanced IP Scanner" nocase ascii wide
                        $string13_advanced_ip_scanner_greyware_tool_keyword = /Advanced_IP_Scanner.{0,1000}\.exe/ nocase ascii wide
                        $string14_advanced_ip_scanner_greyware_tool_keyword = /advanced_ip_scanner_console\.exe/ nocase ascii wide
                        $string15_advanced_ip_scanner_greyware_tool_keyword = /https\:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}