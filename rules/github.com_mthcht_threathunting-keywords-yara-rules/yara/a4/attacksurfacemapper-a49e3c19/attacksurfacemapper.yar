rule AttackSurfaceMapper
{
    meta:
        description = "Detection patterns for the tool 'AttackSurfaceMapper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AttackSurfaceMapper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sasm\.py\s\-t\s.{0,1000}\s\-ln\s\-w\sresources\/.{0,1000}\.txt\s\-o\s/ nocase ascii wide
                        $string2 = /\/AttackSurfaceMapper\.git/ nocase ascii wide
                        $string3 = /\/email_spoof_checks\.txt/
                        $string4 = /\/guessed_emails\.txt/
                        $string5 = "AttackSurfaceMapper-master" nocase ascii wide
                        $string6 = /bitquark_top100k_sublist\.txt/ nocase ascii wide
                        $string7 = /commonspeak_sublist\.txt/ nocase ascii wide
                        $string8 = "superhedgy/AttackSurfaceMapper" nocase ascii wide
                        $string9 = /top100_sublist\.txt/ nocase ascii wide
                        $string10 = /top1000_sublist\.txt/ nocase ascii wide

    condition:
        any of them
}