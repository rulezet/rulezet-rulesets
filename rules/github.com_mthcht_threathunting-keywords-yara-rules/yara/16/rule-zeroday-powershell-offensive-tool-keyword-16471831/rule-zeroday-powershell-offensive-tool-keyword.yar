rule rule_zeroday_powershell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'zeroday-powershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zeroday-powershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_zeroday_powershell_offensive_tool_keyword = "zeroday-powershell" nocase ascii wide

    condition:
        any of them
}