rule arpspoofing
{
    meta:
        description = "Detection patterns for the tool 'arpspoofing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "arpspoofing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/luijait/arpspoofing" nocase ascii wide
                        $string2 = /arpspoofing\.py\s/ nocase ascii wide

    condition:
        any of them
}