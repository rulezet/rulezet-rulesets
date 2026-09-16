rule rule_HostRecon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HostRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HostRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HostRecon_offensive_tool_keyword = "dafthack/HostRecon" nocase ascii wide
                        $string2_HostRecon_offensive_tool_keyword = "Invoke-HostRecon" nocase ascii wide

    condition:
        any of them
}