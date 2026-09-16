rule rule_Internal_Monologue_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Internal-Monologue' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Internal-Monologue"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Internal_Monologue_offensive_tool_keyword = /\s\-Downgrade\sFalse\s\-Restore\sFalse\s\-Impersonate\sTrue\s.{0,1000}\s\-challange\s/ nocase ascii wide
                        $string2_Internal_Monologue_offensive_tool_keyword = /Internal\-Monologue\.exe/ nocase ascii wide
                        $string3_Internal_Monologue_offensive_tool_keyword = "InternalMonologueDll" nocase ascii wide
                        $string4_Internal_Monologue_offensive_tool_keyword = "InternalMonologueExe" nocase ascii wide

    condition:
        any of them
}