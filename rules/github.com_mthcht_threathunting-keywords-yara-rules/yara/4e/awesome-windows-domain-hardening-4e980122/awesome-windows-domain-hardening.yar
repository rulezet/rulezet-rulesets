rule awesome_windows_domain_hardening
{
    meta:
        description = "Detection patterns for the tool 'awesome-windows-domain-hardening' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-windows-domain-hardening"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "awesome-windows-domain-hardening" nocase ascii wide

    condition:
        any of them
}