rule dcipher_cli
{
    meta:
        description = "Detection patterns for the tool 'dcipher-cli' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dcipher-cli"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "dcipher-cli" nocase ascii wide

    condition:
        any of them
}