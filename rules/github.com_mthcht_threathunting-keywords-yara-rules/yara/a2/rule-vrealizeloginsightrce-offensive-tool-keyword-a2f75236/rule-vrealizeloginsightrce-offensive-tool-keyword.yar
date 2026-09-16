rule rule_vRealizeLogInsightRCE_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vRealizeLogInsightRCE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vRealizeLogInsightRCE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_vRealizeLogInsightRCE_offensive_tool_keyword = /\s\-\-payload_file\s.{0,1000}\s\-\-payload_path/ nocase ascii wide
                        $string2_vRealizeLogInsightRCE_offensive_tool_keyword = "/horizon3ai/" nocase ascii wide
                        $string3_vRealizeLogInsightRCE_offensive_tool_keyword = /Downloading\s.{0,1000}\/.{0,1000}\.tar\sto\s\/tmp\/.{0,1000}\.pak/ nocase ascii wide
                        $string4_vRealizeLogInsightRCE_offensive_tool_keyword = /loginsight\.thrift/ nocase ascii wide
                        $string5_vRealizeLogInsightRCE_offensive_tool_keyword = /VMSA\-2023\-0001\.py/ nocase ascii wide
                        $string6_vRealizeLogInsightRCE_offensive_tool_keyword = /VMware\-vRealize\-Log\-Insight\.cert/ nocase ascii wide
                        $string7_vRealizeLogInsightRCE_offensive_tool_keyword = "vRealizeLogInsightRCE" nocase ascii wide

    condition:
        any of them
}