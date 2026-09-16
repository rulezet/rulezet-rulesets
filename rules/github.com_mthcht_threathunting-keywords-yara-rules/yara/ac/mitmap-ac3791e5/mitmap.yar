rule mitmAP
{
    meta:
        description = "Detection patterns for the tool 'mitmAP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmAP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/mitmAP" nocase ascii wide

    condition:
        any of them
}