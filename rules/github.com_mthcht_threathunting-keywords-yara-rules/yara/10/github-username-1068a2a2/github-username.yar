rule Github_Username
{
    meta:
        description = "Detection patterns for the tool 'Github Username' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github Username"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/attackercan/" nocase ascii wide
                        $string2 = "/Ben0xA/" nocase ascii wide
                        $string3 = "BastilleResearch" nocase ascii wide
                        $string4 = "BC-SECURITY" nocase ascii wide
                        $string5 = /guardicore.{0,1000}monkey/ nocase ascii wide
                        $string6 = "s7scan" nocase ascii wide

    condition:
        any of them
}