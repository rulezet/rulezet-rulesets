rule dropmefiles_com
{
    meta:
        description = "Detection patterns for the tool 'dropmefiles.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dropmefiles.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/dropmefiles\.com\// nocase ascii wide
                        $string2 = /https\:\/\/dropmefiles\.com\/s3\/upload\// nocase ascii wide

    condition:
        any of them
}