rule rule_dnscan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnscan_offensive_tool_keyword = /\sdnscan\.py/ nocase ascii wide
                        $string2_dnscan_offensive_tool_keyword = /\/dnscan\.git/ nocase ascii wide
                        $string3_dnscan_offensive_tool_keyword = /\/dnscan\.py/
                        $string4_dnscan_offensive_tool_keyword = /\/subdomains\.txt/
                        $string5_dnscan_offensive_tool_keyword = /\\dnscan\.py/ nocase ascii wide
                        $string6_dnscan_offensive_tool_keyword = "dnscan-master" nocase ascii wide
                        $string7_dnscan_offensive_tool_keyword = "rbsec/dnscan" nocase ascii wide
                        $string8_dnscan_offensive_tool_keyword = /subdomains\-100\.txt/ nocase ascii wide
                        $string9_dnscan_offensive_tool_keyword = /subdomains\-1000\.txt/ nocase ascii wide
                        $string10_dnscan_offensive_tool_keyword = /subdomains\-10000\.txt/ nocase ascii wide
                        $string11_dnscan_offensive_tool_keyword = /subdomains\-500\.txt/ nocase ascii wide
                        $string12_dnscan_offensive_tool_keyword = /subdomains\-uk\-1000\.txt/ nocase ascii wide
                        $string13_dnscan_offensive_tool_keyword = /subdomains\-uk\-500\.txt/ nocase ascii wide

    condition:
        any of them
}