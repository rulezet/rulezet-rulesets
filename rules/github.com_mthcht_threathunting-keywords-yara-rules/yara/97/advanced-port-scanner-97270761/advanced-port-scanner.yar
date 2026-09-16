rule advanced_port_scanner
{
    meta:
        description = "Detection patterns for the tool 'advanced port scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced port scanner"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /\\Advanced_Port_Scanner_.{0,1000}\.exe/ nocase ascii wide
                        $string2 = /Advanced\sPort\sScanner\s\(PUA\)/ nocase ascii wide
                        $string3 = /HackTool\.Win32\.PortScan\.SWO/ nocase ascii wide
                        $string4 = /HTool\-Portscan\.gen/ nocase ascii wide

    condition:
        any of them
}