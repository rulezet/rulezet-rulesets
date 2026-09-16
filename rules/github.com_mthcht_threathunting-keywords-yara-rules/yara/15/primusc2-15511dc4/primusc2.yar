rule primusC2
{
    meta:
        description = "Detection patterns for the tool 'primusC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "primusC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/C2\/server\.py/ nocase ascii wide
                        $string2 = "/PrimusC2" nocase ascii wide
                        $string3 = /\/PrimusC2\.git/ nocase ascii wide
                        $string4 = ":8999/Payloads/" nocase ascii wide
                        $string5 = /127\.0\.0\.1\:4567/ nocase ascii wide
                        $string6 = "localhost:4567" nocase ascii wide
                        $string7 = /PrimusC2\-main\.zip/ nocase ascii wide
                        $string8 = "SELECT displayName FROM AntiVirusProduct" nocase ascii wide
                        $string9 = /ssh\s\-N\s\-R\s4567\:localhost\:.{0,1000}root/ nocase ascii wide

    condition:
        any of them
}