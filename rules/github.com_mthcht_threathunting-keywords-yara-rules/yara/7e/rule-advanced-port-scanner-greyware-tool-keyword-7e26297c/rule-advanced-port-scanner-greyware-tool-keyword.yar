rule rule_advanced_port_scanner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'advanced port scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced port scanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_advanced_port_scanner_greyware_tool_keyword = /\/Advanced_Port_Scanner_.{0,1000}\.exe/ nocase ascii wide
                        $string2_advanced_port_scanner_greyware_tool_keyword = /\/lansearch\.exe/ nocase ascii wide
                        $string3_advanced_port_scanner_greyware_tool_keyword = /\\Advanced\sPort\sScanner\sPortable\\/ nocase ascii wide
                        $string4_advanced_port_scanner_greyware_tool_keyword = /\\lansearch\.exe/ nocase ascii wide
                        $string5_advanced_port_scanner_greyware_tool_keyword = /\\Temp\\2\\Advanced\sPort\sScanner\s2\\/ nocase ascii wide
                        $string6_advanced_port_scanner_greyware_tool_keyword = ">Advanced Port Scanner Setup<" nocase ascii wide
                        $string7_advanced_port_scanner_greyware_tool_keyword = ">Advanced Port Scanner<" nocase ascii wide
                        $string8_advanced_port_scanner_greyware_tool_keyword = /advanced_port_scanner\.exe/ nocase ascii wide
                        $string9_advanced_port_scanner_greyware_tool_keyword = /advanced_port_scanner_console\.exe/ nocase ascii wide
                        $string10_advanced_port_scanner_greyware_tool_keyword = "d0c1662ce239e4d288048c0e3324ec52962f6ddda77da0cb7af9c1d9c2f1e2eb" nocase ascii wide
                        $string11_advanced_port_scanner_greyware_tool_keyword = /http\:\/\/www\.advanced\-port\-scanner\.com\/checkupdate\.php/ nocase ascii wide
                        $string12_advanced_port_scanner_greyware_tool_keyword = /lansearch\.exe\s/ nocase ascii wide
                        $string13_advanced_port_scanner_greyware_tool_keyword = /lansearchpro_portable\.zip/ nocase ascii wide
                        $string14_advanced_port_scanner_greyware_tool_keyword = /lansearchpro_setup\.exe/ nocase ascii wide
                        $string15_advanced_port_scanner_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Advanced\sPort\sScanner\\/ nocase ascii wide

    condition:
        any of them
}