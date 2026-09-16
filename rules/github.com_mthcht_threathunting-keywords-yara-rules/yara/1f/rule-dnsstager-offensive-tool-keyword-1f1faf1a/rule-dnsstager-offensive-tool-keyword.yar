rule rule_DNSStager_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DNSStager' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNSStager"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DNSStager_offensive_tool_keyword = /\sdnsstager\.py/ nocase ascii wide
                        $string2_DNSStager_offensive_tool_keyword = " IPV6 addresses xored " nocase ascii wide
                        $string3_DNSStager_offensive_tool_keyword = /\s\-\-payload\s.{0,1000}\s\-\-shellcode_path\s.{0,1000}\s\-\-xorkey\s/ nocase ascii wide
                        $string4_DNSStager_offensive_tool_keyword = " --payload x64/c/ipv6 " nocase ascii wide
                        $string5_DNSStager_offensive_tool_keyword = /\/DNSStager\.git/ nocase ascii wide
                        $string6_DNSStager_offensive_tool_keyword = /\/dnsstager\.py/ nocase ascii wide
                        $string7_DNSStager_offensive_tool_keyword = /\\dnsstager\.py/ nocase ascii wide
                        $string8_DNSStager_offensive_tool_keyword = /build_c_xor_ipv6\(/ nocase ascii wide
                        $string9_DNSStager_offensive_tool_keyword = /build_c_xor_ipv6_dll\(/ nocase ascii wide
                        $string10_DNSStager_offensive_tool_keyword = /build_golang_xor_ipv6\(/ nocase ascii wide
                        $string11_DNSStager_offensive_tool_keyword = "DNSStager payloads Available" nocase ascii wide
                        $string12_DNSStager_offensive_tool_keyword = "DNSStager will " nocase ascii wide
                        $string13_DNSStager_offensive_tool_keyword = /encode_xor_shellcode\(/ nocase ascii wide
                        $string14_DNSStager_offensive_tool_keyword = "f15f6182ca98bb702c2578efc0aef6e35d8237b89a00a588364bb7e068b132fa" nocase ascii wide
                        $string15_DNSStager_offensive_tool_keyword = "mhaskar/DNSStager" nocase ascii wide
                        $string16_DNSStager_offensive_tool_keyword = "run DNSStager as root" nocase ascii wide
                        $string17_DNSStager_offensive_tool_keyword = /sudo\s\.\/dnsstager/
                        $string18_DNSStager_offensive_tool_keyword = "We recommend to XOR your shellcode before you transfer it" nocase ascii wide

    condition:
        any of them
}