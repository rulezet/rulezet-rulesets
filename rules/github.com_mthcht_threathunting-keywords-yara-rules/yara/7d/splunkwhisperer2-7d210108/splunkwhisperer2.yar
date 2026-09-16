rule SplunkWhisperer2
{
    meta:
        description = "Detection patterns for the tool 'SplunkWhisperer2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SplunkWhisperer2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-payload\-file\spwn\.bat/ nocase ascii wide
                        $string2 = /\s\-\-UserName\s.{0,1000}\s\-\-Password\s.{0,1000}\s\-\-Payload\s.{0,1000}\.exe/ nocase ascii wide
                        $string3 = /\/splunk_whisperer\.git/ nocase ascii wide
                        $string4 = /\/SplunkWhisperer2\.git/ nocase ascii wide
                        $string5 = "airman604/splunk_whisperer" nocase ascii wide
                        $string6 = "cnotin/SplunkWhisperer2" nocase ascii wide
                        $string7 = "PySplunkWhisperer2" nocase ascii wide
                        $string8 = "SharpSplunkWhisperer2" nocase ascii wide
                        $string9 = /splunk_whisperer\.py/ nocase ascii wide
                        $string10 = "splunk_whisperer-master" nocase ascii wide
                        $string11 = "SplunkWhisperer2-master" nocase ascii wide

    condition:
        any of them
}