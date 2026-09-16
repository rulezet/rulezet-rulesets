rule truncate
{
    meta:
        description = "Detection patterns for the tool 'truncate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "truncate"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "truncate -s 0 /var/log/messages"
                        $string2 = "truncate --size=0 /var/log/security"

    condition:
        any of them
}