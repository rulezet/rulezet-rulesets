rule RDPassSpray
{
    meta:
        description = "Detection patterns for the tool 'RDPassSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPassSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/RDPassSpray\.git/ nocase ascii wide
                        $string2 = "62db3e73826eb5cd8b14f3b54e7c476d423f28c0d4e467632fcacf338c250301" nocase ascii wide
                        $string3 = "dafthack/RDPSpray" nocase ascii wide
                        $string4 = /fake_hostnames\(hostnames_list\)/ nocase ascii wide
                        $string5 = /RDPassSpray\..{0,1000}\.log/ nocase ascii wide
                        $string6 = /RDPassSpray\.csv/ nocase ascii wide
                        $string7 = /RDPassSpray\.py/ nocase ascii wide
                        $string8 = "RDPassSpray-main" nocase ascii wide
                        $string9 = "RDPassSpray-master" nocase ascii wide
                        $string10 = "xFreed0m/RDPassSpray" nocase ascii wide
                        $string11 = /xfreerdp\s\/v.{0,1000}SOCtest.{0,1000}AllLegitHere/ nocase ascii wide

    condition:
        any of them
}