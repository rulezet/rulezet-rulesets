rule Seth
{
    meta:
        description = "Detection patterns for the tool 'Seth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Seth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/seth\.sh\s.{0,1000}\s/
                        $string2 = /\.py\s.{0,1000}\s\-\-fake\-server/ nocase ascii wide
                        $string3 = "arpspoof -i " nocase ascii wide
                        $string4 = "Server enforces NLA; switching to 'fake server' mode" nocase ascii wide
                        $string5 = "Seth by SySS GmbH" nocase ascii wide
                        $string6 = /seth\.py\s.{0,1000}\s\-j\sINJECT/ nocase ascii wide
                        $string7 = /Seth\-master\.zip/ nocase ascii wide
                        $string8 = "SySS-Research/Seth" nocase ascii wide

    condition:
        any of them
}