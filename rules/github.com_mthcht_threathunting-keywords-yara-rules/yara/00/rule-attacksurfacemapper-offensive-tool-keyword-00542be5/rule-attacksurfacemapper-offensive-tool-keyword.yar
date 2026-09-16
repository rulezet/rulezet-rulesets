rule rule_AttackSurfaceMapper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AttackSurfaceMapper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AttackSurfaceMapper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AttackSurfaceMapper_offensive_tool_keyword = /\sasm\.py\s\-t\s.{0,1000}\s\-ln\s\-w\sresources\/.{0,1000}\.txt\s\-o\s/ nocase ascii wide
                        $string2_AttackSurfaceMapper_offensive_tool_keyword = /\/AttackSurfaceMapper\.git/ nocase ascii wide
                        $string3_AttackSurfaceMapper_offensive_tool_keyword = /\/email_spoof_checks\.txt/
                        $string4_AttackSurfaceMapper_offensive_tool_keyword = /\/guessed_emails\.txt/
                        $string5_AttackSurfaceMapper_offensive_tool_keyword = "AttackSurfaceMapper-master" nocase ascii wide
                        $string6_AttackSurfaceMapper_offensive_tool_keyword = /bitquark_top100k_sublist\.txt/ nocase ascii wide
                        $string7_AttackSurfaceMapper_offensive_tool_keyword = /commonspeak_sublist\.txt/ nocase ascii wide
                        $string8_AttackSurfaceMapper_offensive_tool_keyword = "superhedgy/AttackSurfaceMapper" nocase ascii wide
                        $string9_AttackSurfaceMapper_offensive_tool_keyword = /top100_sublist\.txt/ nocase ascii wide
                        $string10_AttackSurfaceMapper_offensive_tool_keyword = /top1000_sublist\.txt/ nocase ascii wide

    condition:
        any of them
}