rule rule_crypto_identifier_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crypto_identifier' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crypto_identifier"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_crypto_identifier_offensive_tool_keyword = "crypto_identifier" nocase ascii wide

    condition:
        any of them
}