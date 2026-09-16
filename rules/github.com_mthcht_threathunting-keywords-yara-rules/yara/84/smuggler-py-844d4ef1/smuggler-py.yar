rule smuggler_py
{
    meta:
        description = "Detection patterns for the tool 'smuggler.py' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smuggler.py"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\ssmuggler\.py/ nocase ascii wide
                        $string2 = /\/smuggler\.py/ nocase ascii wide
                        $string3 = /\\smuggler\.py/ nocase ascii wide

    condition:
        any of them
}