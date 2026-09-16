rule vRealizeLogInsightRCE
{
    meta:
        description = "Detection patterns for the tool 'vRealizeLogInsightRCE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vRealizeLogInsightRCE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-payload_file\s.{0,1000}\s\-\-payload_path/ nocase ascii wide
                        $string2 = "/horizon3ai/" nocase ascii wide
                        $string3 = /Downloading\s.{0,1000}\/.{0,1000}\.tar\sto\s\/tmp\/.{0,1000}\.pak/ nocase ascii wide
                        $string4 = /loginsight\.thrift/ nocase ascii wide
                        $string5 = /VMSA\-2023\-0001\.py/ nocase ascii wide
                        $string6 = /VMware\-vRealize\-Log\-Insight\.cert/ nocase ascii wide
                        $string7 = "vRealizeLogInsightRCE" nocase ascii wide

    condition:
        any of them
}