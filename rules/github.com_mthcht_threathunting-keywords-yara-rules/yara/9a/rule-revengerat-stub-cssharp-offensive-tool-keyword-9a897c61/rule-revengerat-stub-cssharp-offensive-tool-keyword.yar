rule rule_RevengeRAT_Stub_Cssharp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RevengeRAT-Stub-Cssharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RevengeRAT-Stub-Cssharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RevengeRAT_Stub_Cssharp_offensive_tool_keyword = "052C26C0-7979-4555-89CE-34C5CE8D8B34" nocase ascii wide
                        $string2_RevengeRAT_Stub_Cssharp_offensive_tool_keyword = "9ae37b21e20b611787f1219137b545597235c23fd54c0e73919b9ae3266bd046" nocase ascii wide
                        $string3_RevengeRAT_Stub_Cssharp_offensive_tool_keyword = "c4f026c01e451e1afa61ab8233fd15a3c0b4da615eae5d893db82b84bbe49e40" nocase ascii wide
                        $string4_RevengeRAT_Stub_Cssharp_offensive_tool_keyword = "RevengeRAT-Stub-CSsharp" nocase ascii wide

    condition:
        any of them
}