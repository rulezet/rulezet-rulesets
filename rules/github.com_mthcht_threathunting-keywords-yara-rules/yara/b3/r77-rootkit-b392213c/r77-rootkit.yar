rule r77_rootkit
{
    meta:
        description = "Detection patterns for the tool 'r77-rootkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "r77-rootkit"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "Trojan:Win64/r77RootKit" nocase ascii wide

    condition:
        any of them
}