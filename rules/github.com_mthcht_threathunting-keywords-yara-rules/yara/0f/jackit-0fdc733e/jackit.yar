rule jackit
{
    meta:
        description = "Detection patterns for the tool 'jackit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jackit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/jackit" nocase ascii wide
                        $string2 = /insecurityofthings.{0,1000}jackit/ nocase ascii wide

    condition:
        any of them
}