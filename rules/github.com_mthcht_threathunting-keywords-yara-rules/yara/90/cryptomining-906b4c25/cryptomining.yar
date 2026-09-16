rule cryptomining
{
    meta:
        description = "Detection patterns for the tool 'cryptomining' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cryptomining"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "Linux/CoinMiner" nocase ascii wide
                        $string2 = /Linux\/CoinMiner\.NM/ nocase ascii wide
                        $string3 = /LINUX\/CoinMiner\.wgudk/ nocase ascii wide

    condition:
        any of them
}