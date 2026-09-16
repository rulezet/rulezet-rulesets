rule dnscan
{
    meta:
        description = "Detection patterns for the tool 'dnscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdnscan\.py/ nocase ascii wide
                        $string2 = /\/dnscan\.git/ nocase ascii wide
                        $string3 = /\/dnscan\.py/
                        $string4 = /\/subdomains\.txt/
                        $string5 = /\\dnscan\.py/ nocase ascii wide
                        $string6 = "dnscan-master" nocase ascii wide
                        $string7 = "rbsec/dnscan" nocase ascii wide
                        $string8 = /subdomains\-100\.txt/ nocase ascii wide
                        $string9 = /subdomains\-1000\.txt/ nocase ascii wide
                        $string10 = /subdomains\-10000\.txt/ nocase ascii wide
                        $string11 = /subdomains\-500\.txt/ nocase ascii wide
                        $string12 = /subdomains\-uk\-1000\.txt/ nocase ascii wide
                        $string13 = /subdomains\-uk\-500\.txt/ nocase ascii wide

    condition:
        any of them
}