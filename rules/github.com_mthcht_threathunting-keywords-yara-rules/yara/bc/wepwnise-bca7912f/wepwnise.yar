rule wePWNise
{
    meta:
        description = "Detection patterns for the tool 'wePWNise' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wePWNise"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "wePWNise" nocase ascii wide

    condition:
        any of them
}