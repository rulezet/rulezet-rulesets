rule ip_api_com
{
    meta:
        description = "Detection patterns for the tool 'ip-api.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ip-api.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /www\.ip\-api\.com/ nocase ascii wide

    condition:
        any of them
}