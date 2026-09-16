rule windows_privesc_check
{
    meta:
        description = "Detection patterns for the tool 'windows-privesc-check' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-privesc-check"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "privesc-check" nocase ascii wide

    condition:
        any of them
}