rule rule_passphrase_wordlist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'passphrase-wordlist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passphrase-wordlist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_passphrase_wordlist_offensive_tool_keyword = "passphrase-wordlist" nocase ascii wide

    condition:
        any of them
}