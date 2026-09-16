rule ldapminer
{
    meta:
        description = "Detection patterns for the tool 'ldapminer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapminer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "LdapMiner" nocase ascii wide

    condition:
        any of them
}