rule rengine
{
    meta:
        description = "Detection patterns for the tool 'rengine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rengine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "yogeshojha/rengine" nocase ascii wide

    condition:
        any of them
}