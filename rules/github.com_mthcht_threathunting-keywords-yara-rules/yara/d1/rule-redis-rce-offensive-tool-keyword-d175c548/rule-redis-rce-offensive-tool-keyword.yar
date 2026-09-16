rule rule_redis_rce_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'redis-rce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redis-rce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_redis_rce_offensive_tool_keyword = "redis-rce" nocase ascii wide

    condition:
        any of them
}