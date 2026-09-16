rule rule_Nordic_NRF52840_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nordic NRF52840' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nordic NRF52840"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Nordic_NRF52840_offensive_tool_keyword = /USB\\VID_1915\&PID_520C\&MI_00\\6\&20A3E423/ nocase ascii wide

    condition:
        any of them
}