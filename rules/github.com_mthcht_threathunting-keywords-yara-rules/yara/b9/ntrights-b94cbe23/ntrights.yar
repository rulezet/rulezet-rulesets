rule NtRights
{
    meta:
        description = "Detection patterns for the tool 'NtRights' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtRights"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/NtRights/" nocase ascii wide
                        $string2 = /\\NtRights\\/ nocase ascii wide
                        $string3 = /ntrights\.exe/ nocase ascii wide

    condition:
        any of them
}