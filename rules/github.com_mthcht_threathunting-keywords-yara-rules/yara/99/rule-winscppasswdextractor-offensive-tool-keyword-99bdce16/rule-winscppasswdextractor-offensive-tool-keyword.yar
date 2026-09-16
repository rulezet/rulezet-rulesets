rule rule_WinSCPPasswdExtractor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WinSCPPasswdExtractor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinSCPPasswdExtractor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WinSCPPasswdExtractor_offensive_tool_keyword = "WinSCPPasswdExtractor" nocase ascii wide

    condition:
        any of them
}