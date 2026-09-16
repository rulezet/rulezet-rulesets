rule rule_reverse_shell_generator_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'reverse-shell-generator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-shell-generator"
        rule_category = "signature_keyword"

    strings:
                        $string1_reverse_shell_generator_signature_keyword = /Trojan\:PowerShell\/ReverseShell\./ nocase ascii wide

    condition:
        any of them
}