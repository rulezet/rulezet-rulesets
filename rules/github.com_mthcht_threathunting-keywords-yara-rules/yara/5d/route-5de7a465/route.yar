rule route
{
    meta:
        description = "Detection patterns for the tool 'route' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "route"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\Windows\\system32\\ROUTE\.EXE\\"\sprint/ nocase ascii wide

    condition:
        any of them
}