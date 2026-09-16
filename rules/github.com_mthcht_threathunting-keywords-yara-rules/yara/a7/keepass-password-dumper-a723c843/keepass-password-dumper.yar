rule keepass_password_dumper
{
    meta:
        description = "Detection patterns for the tool 'keepass-password-dumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keepass-password-dumper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "keepass-password-dumper" nocase ascii wide

    condition:
        any of them
}