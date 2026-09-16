rule PowerShellArsenal
{
    meta:
        description = "Detection patterns for the tool 'PowerShellArsenal' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShellArsenal"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "PowerShellArsenal" nocase ascii wide

    condition:
        any of them
}