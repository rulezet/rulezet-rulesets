rule rule_MutationGate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MutationGate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MutationGate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MutationGate_offensive_tool_keyword = /\sMutationGate\.cpp/ nocase ascii wide
                        $string2_MutationGate_offensive_tool_keyword = /\/MutationGate\.git/ nocase ascii wide
                        $string3_MutationGate_offensive_tool_keyword = /\\MutationGate\.cpp/ nocase ascii wide
                        $string4_MutationGate_offensive_tool_keyword = /\\MutationGate\.exe/ nocase ascii wide
                        $string5_MutationGate_offensive_tool_keyword = /\\MutationGate\.sln/ nocase ascii wide
                        $string6_MutationGate_offensive_tool_keyword = /\\MutationGate\.vcxproj/ nocase ascii wide
                        $string7_MutationGate_offensive_tool_keyword = "5A0FBE0D-BACC-4B97-8578-B5B27567EEA7" nocase ascii wide
                        $string8_MutationGate_offensive_tool_keyword = "dd3cd4783ec400f215c4f72f797fe310be12453c20944feec054a449835feb36" nocase ascii wide
                        $string9_MutationGate_offensive_tool_keyword = "senzee1984/MutationGate" nocase ascii wide

    condition:
        any of them
}