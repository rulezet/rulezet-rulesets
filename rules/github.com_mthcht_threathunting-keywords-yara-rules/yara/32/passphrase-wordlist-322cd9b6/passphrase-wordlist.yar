rule passphrase_wordlist
{
    meta:
        description = "Detection patterns for the tool 'passphrase-wordlist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passphrase-wordlist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "passphrase-wordlist" nocase ascii wide

    condition:
        any of them
}