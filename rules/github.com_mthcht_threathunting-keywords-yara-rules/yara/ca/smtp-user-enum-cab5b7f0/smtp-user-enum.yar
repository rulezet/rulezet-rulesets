rule smtp_user_enum
{
    meta:
        description = "Detection patterns for the tool 'smtp-user-enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smtp-user-enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/smtp-user-enum" nocase ascii wide
                        $string2 = "smtp-user-enum" nocase ascii wide

    condition:
        any of them
}