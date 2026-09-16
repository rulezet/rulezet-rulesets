rule rule__0day_today_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '0day.today' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "0day.today"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__0day_today_offensive_tool_keyword = /https\:\/\/0day\.today\/exploit\// nocase ascii wide

    condition:
        any of them
}