rule Sitadel
{
    meta:
        description = "Detection patterns for the tool 'Sitadel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sitadel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -a bruteforce " nocase ascii wide
                        $string2 = " --attack bruteforce" nocase ascii wide
                        $string3 = " --attack injection" nocase ascii wide
                        $string4 = " --attack vulns " nocase ascii wide
                        $string5 = /\ssitadel\.py/ nocase ascii wide
                        $string6 = /\/Sitadel\.git/ nocase ascii wide
                        $string7 = /\/sitadel\.log/ nocase ascii wide
                        $string8 = /\/sitadel\.py/ nocase ascii wide
                        $string9 = /\\sitadel\.log/ nocase ascii wide
                        $string10 = "docker run sitadel" nocase ascii wide
                        $string11 = "python3 sitadel" nocase ascii wide
                        $string12 = "sitadel http://" nocase ascii wide
                        $string13 = "sitadel https://" nocase ascii wide
                        $string14 = /sitadel\.py\s/ nocase ascii wide
                        $string15 = /Sitadel\-master\.zip/ nocase ascii wide

    condition:
        any of them
}