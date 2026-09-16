rule rule_NtRights_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NtRights' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtRights"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NtRights_offensive_tool_keyword = "/NtRights/" nocase ascii wide
                        $string2_NtRights_offensive_tool_keyword = /\\NtRights\\/ nocase ascii wide
                        $string3_NtRights_offensive_tool_keyword = /ntrights\.exe/ nocase ascii wide

    condition:
        any of them
}