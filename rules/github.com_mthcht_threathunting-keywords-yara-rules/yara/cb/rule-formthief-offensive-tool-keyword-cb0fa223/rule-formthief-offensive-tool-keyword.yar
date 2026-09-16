rule rule_FormThief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FormThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FormThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FormThief_offensive_tool_keyword = /\/FormThief\.git/ nocase ascii wide
                        $string2_FormThief_offensive_tool_keyword = /\\FormThief\-main/ nocase ascii wide
                        $string3_FormThief_offensive_tool_keyword = "10CC4D5B-DC87-4AEB-887B-E47367BF656B" nocase ascii wide
                        $string4_FormThief_offensive_tool_keyword = "4B2E3A60-9A8F-4F36-8692-14ED9887E7BE" nocase ascii wide
                        $string5_FormThief_offensive_tool_keyword = "4ED3C17D-33E6-4B86-9FA0-DA774B7CD387" nocase ascii wide
                        $string6_FormThief_offensive_tool_keyword = "78DE9716-84E8-4469-A5AE-F3E43181C28B" nocase ascii wide
                        $string7_FormThief_offensive_tool_keyword = "D6948EFC-AA15-413D-8EF1-032C149D3FBB" nocase ascii wide
                        $string8_FormThief_offensive_tool_keyword = "mlcsec/FormThief" nocase ascii wide

    condition:
        any of them
}