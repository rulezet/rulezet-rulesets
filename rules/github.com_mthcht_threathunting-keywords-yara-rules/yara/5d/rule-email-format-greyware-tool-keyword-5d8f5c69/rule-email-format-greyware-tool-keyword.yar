rule rule_email_format_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'email-format' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "email-format"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_email_format_greyware_tool_keyword = /https\:\/\/www\.email\-format\.com\/d\// nocase ascii wide

    condition:
        any of them
}