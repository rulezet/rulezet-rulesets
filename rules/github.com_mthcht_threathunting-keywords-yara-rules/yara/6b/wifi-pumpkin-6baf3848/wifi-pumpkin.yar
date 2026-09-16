rule WiFi_Pumpkin
{
    meta:
        description = "Detection patterns for the tool 'WiFi-Pumpkin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WiFi-Pumpkin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "WiFi-Pumpkin" nocase ascii wide

    condition:
        any of them
}