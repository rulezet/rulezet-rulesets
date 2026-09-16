rule advanced_ip_scanner
{
    meta:
        description = "Detection patterns for the tool 'advanced-ip-scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced-ip-scanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.exe\s\/s\:ip_ranges\.txt\s\/f\:scan_results\.txt/ nocase ascii wide
                        $string2 = /\\Advanced\sIP\sScanner\.lnk/ nocase ascii wide
                        $string3 = /\\advanced_ip_scanner/ nocase ascii wide
                        $string4 = /\\Local\\Temp\\Advanced\sIP\sScanner\s2\\/ nocase ascii wide
                        $string5 = /\\Program\sFiles\s\(x86\)\\Advanced\sIP\sScanner\\/ nocase ascii wide
                        $string6 = /\\Programs\\Advanced\sIP\sScanner\sPortable\\/ nocase ascii wide
                        $string7 = /\\Start\sMenu\\Programs\\Advanced\sIP\sScanner\sv2/ nocase ascii wide
                        $string8 = ">Advanced IP Scanner Setup<" nocase ascii wide
                        $string9 = ">Advanced IP Scanner<" nocase ascii wide
                        $string10 = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b" nocase ascii wide
                        $string11 = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b" nocase ascii wide
                        $string12 = "Advanced IP Scanner" nocase ascii wide
                        $string13 = /Advanced_IP_Scanner.{0,1000}\.exe/ nocase ascii wide
                        $string14 = /advanced_ip_scanner_console\.exe/ nocase ascii wide
                        $string15 = /https\:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}