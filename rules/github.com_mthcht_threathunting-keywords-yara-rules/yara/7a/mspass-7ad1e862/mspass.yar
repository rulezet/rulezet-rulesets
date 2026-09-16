rule mspass
{
    meta:
        description = "Detection patterns for the tool 'mspass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mspass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /mspass\.exe/ nocase ascii wide
                        $string2 = /mspass\.zip/ nocase ascii wide

    condition:
        any of them
}