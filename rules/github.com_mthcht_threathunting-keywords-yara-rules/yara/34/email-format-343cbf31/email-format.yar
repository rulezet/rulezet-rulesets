rule email_format
{
    meta:
        description = "Detection patterns for the tool 'email-format' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "email-format"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/www\.email\-format\.com\/d\// nocase ascii wide

    condition:
        any of them
}