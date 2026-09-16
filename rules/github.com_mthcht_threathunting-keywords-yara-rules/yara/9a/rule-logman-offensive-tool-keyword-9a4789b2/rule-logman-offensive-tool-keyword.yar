rule rule_logman_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'logman' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "logman"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_logman_offensive_tool_keyword = "logman update trace EventLog-Application --p Microsoft-Windows-PowerShell -ets" nocase ascii wide

    condition:
        any of them
}