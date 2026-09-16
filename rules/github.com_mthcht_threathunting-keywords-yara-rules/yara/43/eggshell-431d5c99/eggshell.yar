rule Eggshell
{
    meta:
        description = "Detection patterns for the tool 'Eggshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eggshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /EggShell\.py/ nocase ascii wide

    condition:
        any of them
}