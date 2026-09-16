rule ADFSRelay
{
    meta:
        description = "Detection patterns for the tool 'ADFSRelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSRelay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\|\sNTLMParse/ nocase ascii wide
                        $string2 = /\/ADFSRelay\.git/ nocase ascii wide
                        $string3 = /\/ADFSRelay\.go/ nocase ascii wide
                        $string4 = /\/NTLMParse\.go/ nocase ascii wide
                        $string5 = /\/releases\/download\/v1\.0\/ADFSRelay/ nocase ascii wide
                        $string6 = /\/releases\/download\/v1\.0\/NTLMParse/ nocase ascii wide
                        $string7 = /\\ADFSRelay\\/ nocase ascii wide
                        $string8 = "ADFSRelay -" nocase ascii wide
                        $string9 = "ADFSRelay-main" nocase ascii wide
                        $string10 = /praetorian\.com\/blog\/relaying\-to\-adfs\-attacks\// nocase ascii wide
                        $string11 = "praetorian-inc/ADFSRelay" nocase ascii wide

    condition:
        any of them
}