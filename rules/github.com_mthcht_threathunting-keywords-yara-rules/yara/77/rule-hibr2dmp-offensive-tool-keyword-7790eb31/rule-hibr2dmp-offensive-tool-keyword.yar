rule rule_Hibr2Dmp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hibr2Dmp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hibr2Dmp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hibr2Dmp_offensive_tool_keyword = /Hibr2Dmp\.exe/ nocase ascii wide

    condition:
        any of them
}