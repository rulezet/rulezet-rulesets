rule rule_SplunkWhisperer2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SplunkWhisperer2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SplunkWhisperer2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SplunkWhisperer2_offensive_tool_keyword = /\s\-\-payload\-file\spwn\.bat/ nocase ascii wide
                        $string2_SplunkWhisperer2_offensive_tool_keyword = /\s\-\-UserName\s.{0,1000}\s\-\-Password\s.{0,1000}\s\-\-Payload\s.{0,1000}\.exe/ nocase ascii wide
                        $string3_SplunkWhisperer2_offensive_tool_keyword = /\/splunk_whisperer\.git/ nocase ascii wide
                        $string4_SplunkWhisperer2_offensive_tool_keyword = /\/SplunkWhisperer2\.git/ nocase ascii wide
                        $string5_SplunkWhisperer2_offensive_tool_keyword = "airman604/splunk_whisperer" nocase ascii wide
                        $string6_SplunkWhisperer2_offensive_tool_keyword = "cnotin/SplunkWhisperer2" nocase ascii wide
                        $string7_SplunkWhisperer2_offensive_tool_keyword = "PySplunkWhisperer2" nocase ascii wide
                        $string8_SplunkWhisperer2_offensive_tool_keyword = "SharpSplunkWhisperer2" nocase ascii wide
                        $string9_SplunkWhisperer2_offensive_tool_keyword = /splunk_whisperer\.py/ nocase ascii wide
                        $string10_SplunkWhisperer2_offensive_tool_keyword = "splunk_whisperer-master" nocase ascii wide
                        $string11_SplunkWhisperer2_offensive_tool_keyword = "SplunkWhisperer2-master" nocase ascii wide

    condition:
        any of them
}