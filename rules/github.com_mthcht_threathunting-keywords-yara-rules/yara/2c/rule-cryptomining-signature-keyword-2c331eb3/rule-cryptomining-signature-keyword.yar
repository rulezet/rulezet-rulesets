rule rule_cryptomining_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'cryptomining' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cryptomining"
        rule_category = "signature_keyword"

    strings:
                        $string1_cryptomining_signature_keyword = "Linux/CoinMiner" nocase ascii wide
                        $string2_cryptomining_signature_keyword = /Linux\/CoinMiner\.NM/ nocase ascii wide
                        $string3_cryptomining_signature_keyword = /LINUX\/CoinMiner\.wgudk/ nocase ascii wide

    condition:
        any of them
}