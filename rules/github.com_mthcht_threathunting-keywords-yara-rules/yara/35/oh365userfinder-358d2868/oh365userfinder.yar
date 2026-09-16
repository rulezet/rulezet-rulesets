rule Oh365UserFinder
{
    meta:
        description = "Detection patterns for the tool 'Oh365UserFinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Oh365UserFinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Oh365UserFinder" nocase ascii wide
                        $string2 = /Oh365UserFinder\.git/ nocase ascii wide
                        $string3 = /oh365userfinder\.py/ nocase ascii wide
                        $string4 = "Oh365UserFinder-main" nocase ascii wide

    condition:
        any of them
}