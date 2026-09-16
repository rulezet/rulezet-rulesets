rule redis_rce
{
    meta:
        description = "Detection patterns for the tool 'redis-rce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redis-rce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "redis-rce" nocase ascii wide

    condition:
        any of them
}