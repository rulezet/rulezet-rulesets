rule logman
{
    meta:
        description = "Detection patterns for the tool 'logman' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "logman"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "logman update trace EventLog-Application --p Microsoft-Windows-PowerShell -ets" nocase ascii wide

    condition:
        any of them
}