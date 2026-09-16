rule ASREPRoast
{
    meta:
        description = "Detection patterns for the tool 'ASREPRoast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ASREPRoast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ASREPRoast" nocase ascii wide
                        $string2 = /ASREPRoast\.ps1/ nocase ascii wide
                        $string3 = "crackTGS" nocase ascii wide
                        $string4 = "Invoke-ASREPRoast" nocase ascii wide
                        $string5 = /tgscrack\.go/ nocase ascii wide

    condition:
        any of them
}