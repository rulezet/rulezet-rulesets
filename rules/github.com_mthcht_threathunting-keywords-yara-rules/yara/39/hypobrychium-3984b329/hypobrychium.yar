rule hypobrychium
{
    meta:
        description = "Detection patterns for the tool 'hypobrychium' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hypobrychium"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/hypobrychium\.git/ nocase ascii wide
                        $string2 = "foxlox/hypobrychium" nocase ascii wide
                        $string3 = /hypobrychium\.exe/ nocase ascii wide
                        $string4 = "hypobrychium-main" nocase ascii wide

    condition:
        any of them
}