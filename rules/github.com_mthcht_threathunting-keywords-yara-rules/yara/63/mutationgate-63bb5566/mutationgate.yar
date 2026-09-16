rule MutationGate
{
    meta:
        description = "Detection patterns for the tool 'MutationGate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MutationGate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sMutationGate\.cpp/ nocase ascii wide
                        $string2 = /\/MutationGate\.git/ nocase ascii wide
                        $string3 = /\\MutationGate\.cpp/ nocase ascii wide
                        $string4 = /\\MutationGate\.exe/ nocase ascii wide
                        $string5 = /\\MutationGate\.sln/ nocase ascii wide
                        $string6 = /\\MutationGate\.vcxproj/ nocase ascii wide
                        $string7 = "5A0FBE0D-BACC-4B97-8578-B5B27567EEA7" nocase ascii wide
                        $string8 = "dd3cd4783ec400f215c4f72f797fe310be12453c20944feec054a449835feb36" nocase ascii wide
                        $string9 = "senzee1984/MutationGate" nocase ascii wide

    condition:
        any of them
}