rule ducktail
{
    meta:
        description = "Detection patterns for the tool 'ducktail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ducktail"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\-\-headless\s\-\-disable\-gpu\s\-\-disable\-logging\s\-\-dump\-dom\shttps\:\/\/getip\.pro/ nocase ascii wide

    condition:
        any of them
}