rule advanced_port_scanner
{
    meta:
        description = "Detection patterns for the tool 'advanced port scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced port scanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/Advanced_Port_Scanner_.{0,1000}\.exe/ nocase ascii wide
                        $string2 = /\/lansearch\.exe/ nocase ascii wide
                        $string3 = /\\Advanced\sPort\sScanner\sPortable\\/ nocase ascii wide
                        $string4 = /\\lansearch\.exe/ nocase ascii wide
                        $string5 = /\\Temp\\2\\Advanced\sPort\sScanner\s2\\/ nocase ascii wide
                        $string6 = ">Advanced Port Scanner Setup<" nocase ascii wide
                        $string7 = ">Advanced Port Scanner<" nocase ascii wide
                        $string8 = /advanced_port_scanner\.exe/ nocase ascii wide
                        $string9 = /advanced_port_scanner_console\.exe/ nocase ascii wide
                        $string10 = "d0c1662ce239e4d288048c0e3324ec52962f6ddda77da0cb7af9c1d9c2f1e2eb" nocase ascii wide
                        $string11 = /http\:\/\/www\.advanced\-port\-scanner\.com\/checkupdate\.php/ nocase ascii wide
                        $string12 = /lansearch\.exe\s/ nocase ascii wide
                        $string13 = /lansearchpro_portable\.zip/ nocase ascii wide
                        $string14 = /lansearchpro_setup\.exe/ nocase ascii wide
                        $string15 = /Program\sFiles\s\(x86\)\\Advanced\sPort\sScanner\\/ nocase ascii wide

    condition:
        any of them
}