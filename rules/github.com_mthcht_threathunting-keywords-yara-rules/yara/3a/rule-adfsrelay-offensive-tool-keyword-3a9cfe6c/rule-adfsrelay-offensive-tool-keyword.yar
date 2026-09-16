rule rule_ADFSRelay_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADFSRelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSRelay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADFSRelay_offensive_tool_keyword = /\s\|\sNTLMParse/ nocase ascii wide
                        $string2_ADFSRelay_offensive_tool_keyword = /\/ADFSRelay\.git/ nocase ascii wide
                        $string3_ADFSRelay_offensive_tool_keyword = /\/ADFSRelay\.go/ nocase ascii wide
                        $string4_ADFSRelay_offensive_tool_keyword = /\/NTLMParse\.go/ nocase ascii wide
                        $string5_ADFSRelay_offensive_tool_keyword = /\/releases\/download\/v1\.0\/ADFSRelay/ nocase ascii wide
                        $string6_ADFSRelay_offensive_tool_keyword = /\/releases\/download\/v1\.0\/NTLMParse/ nocase ascii wide
                        $string7_ADFSRelay_offensive_tool_keyword = /\\ADFSRelay\\/ nocase ascii wide
                        $string8_ADFSRelay_offensive_tool_keyword = "ADFSRelay -" nocase ascii wide
                        $string9_ADFSRelay_offensive_tool_keyword = "ADFSRelay-main" nocase ascii wide
                        $string10_ADFSRelay_offensive_tool_keyword = /praetorian\.com\/blog\/relaying\-to\-adfs\-attacks\// nocase ascii wide
                        $string11_ADFSRelay_offensive_tool_keyword = "praetorian-inc/ADFSRelay" nocase ascii wide

    condition:
        any of them
}