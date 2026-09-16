rule rule_DNSExfiltrator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DNSExfiltrator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNSExfiltrator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DNSExfiltrator_offensive_tool_keyword = /\$DNSExfiltratorLib/ nocase ascii wide
                        $string2_DNSExfiltrator_offensive_tool_keyword = "/DNSExfiltrator" nocase ascii wide
                        $string3_DNSExfiltrator_offensive_tool_keyword = /\/dnsExfiltrator\.dll/ nocase ascii wide
                        $string4_DNSExfiltrator_offensive_tool_keyword = /\/DNSExfiltrator\.git/ nocase ascii wide
                        $string5_DNSExfiltrator_offensive_tool_keyword = /\/dnsexfiltrator\.py/ nocase ascii wide
                        $string6_DNSExfiltrator_offensive_tool_keyword = /\\dnsExfiltrator\.cs/ nocase ascii wide
                        $string7_DNSExfiltrator_offensive_tool_keyword = /\\dnsExfiltrator\.dll/ nocase ascii wide
                        $string8_DNSExfiltrator_offensive_tool_keyword = /\\dnsexfiltrator\.py/ nocase ascii wide
                        $string9_DNSExfiltrator_offensive_tool_keyword = "5cf800056e1db3399b0f3dd19eed7c0ae2c187816c2a0e0da36191154726fb38" nocase ascii wide
                        $string10_DNSExfiltrator_offensive_tool_keyword = "Arno0x/DNSExfiltrator" nocase ascii wide
                        $string11_DNSExfiltrator_offensive_tool_keyword = "cf840440b78deadaf6f4f085db860d3bc69ce480edc505a378f733127ff37bc6" nocase ascii wide
                        $string12_DNSExfiltrator_offensive_tool_keyword = "dec6b9f665b6679c1c9bedbd9d51ea9faf76f29619b7cc4892f22b9659719335" nocase ascii wide
                        $string13_DNSExfiltrator_offensive_tool_keyword = /dnsExfiltrator\.exe/ nocase ascii wide
                        $string14_DNSExfiltrator_offensive_tool_keyword = "DNSExfiltratorLib" nocase ascii wide
                        $string15_DNSExfiltrator_offensive_tool_keyword = "e3991de30b4675d89877b4b22a36e71c1ac11b399e9b6826195e87354f4d6837" nocase ascii wide
                        $string16_DNSExfiltrator_offensive_tool_keyword = "ed937bcd5dc05f1021aa83afdb47af266083ef47228e23a32292bad577c53191" nocase ascii wide
                        $string17_DNSExfiltrator_offensive_tool_keyword = "f079fee94bbb57fd41bab9139839f5458137b0a8bcd692642f22f08ce647cae2" nocase ascii wide
                        $string18_DNSExfiltrator_offensive_tool_keyword = "Invoke-DNSExfiltrator" nocase ascii wide

    condition:
        any of them
}