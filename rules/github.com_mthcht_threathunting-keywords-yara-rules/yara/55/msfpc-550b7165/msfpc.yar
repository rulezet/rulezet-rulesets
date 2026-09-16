rule msfpc
{
    meta:
        description = "Detection patterns for the tool 'msfpc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msfpc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/msfpc\.sh/ nocase ascii wide
                        $string2 = /msfpc\.sh/ nocase ascii wide

    condition:
        any of them
}