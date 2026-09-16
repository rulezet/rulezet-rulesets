rule rule_RDPassSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RDPassSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPassSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RDPassSpray_offensive_tool_keyword = /\/RDPassSpray\.git/ nocase ascii wide
                        $string2_RDPassSpray_offensive_tool_keyword = "62db3e73826eb5cd8b14f3b54e7c476d423f28c0d4e467632fcacf338c250301" nocase ascii wide
                        $string3_RDPassSpray_offensive_tool_keyword = "dafthack/RDPSpray" nocase ascii wide
                        $string4_RDPassSpray_offensive_tool_keyword = /fake_hostnames\(hostnames_list\)/ nocase ascii wide
                        $string5_RDPassSpray_offensive_tool_keyword = /RDPassSpray\..{0,1000}\.log/ nocase ascii wide
                        $string6_RDPassSpray_offensive_tool_keyword = /RDPassSpray\.csv/ nocase ascii wide
                        $string7_RDPassSpray_offensive_tool_keyword = /RDPassSpray\.py/ nocase ascii wide
                        $string8_RDPassSpray_offensive_tool_keyword = "RDPassSpray-main" nocase ascii wide
                        $string9_RDPassSpray_offensive_tool_keyword = "RDPassSpray-master" nocase ascii wide
                        $string10_RDPassSpray_offensive_tool_keyword = "xFreed0m/RDPassSpray" nocase ascii wide
                        $string11_RDPassSpray_offensive_tool_keyword = /xfreerdp\s\/v.{0,1000}SOCtest.{0,1000}AllLegitHere/ nocase ascii wide

    condition:
        any of them
}