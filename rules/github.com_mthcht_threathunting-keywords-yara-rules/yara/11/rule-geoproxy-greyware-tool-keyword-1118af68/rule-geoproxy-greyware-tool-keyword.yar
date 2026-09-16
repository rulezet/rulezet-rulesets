rule rule_GeoProxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GeoProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GeoProxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_GeoProxy_greyware_tool_keyword = "pooljnboifbodgifngpppfklhifechoe" nocase ascii wide

    condition:
        any of them
}