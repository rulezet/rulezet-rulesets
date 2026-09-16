rule rule_windows_defender_remover_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'windows-defender-remover' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-defender-remover"
        rule_category = "signature_keyword"

    strings:
                        $string1_windows_defender_remover_signature_keyword = /\/WinREG\.KillAV/ nocase ascii wide
                        $string2_windows_defender_remover_signature_keyword = /REG\/KillAV\.A/ nocase ascii wide
                        $string3_windows_defender_remover_signature_keyword = "Win32/DefenderRmv" nocase ascii wide

    condition:
        any of them
}