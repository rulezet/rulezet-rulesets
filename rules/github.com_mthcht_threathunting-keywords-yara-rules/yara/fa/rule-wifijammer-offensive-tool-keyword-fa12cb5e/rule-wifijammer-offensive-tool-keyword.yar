rule rule_wifijammer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wifijammer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifijammer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wifijammer_offensive_tool_keyword = "hash3liZer/wifijammer" nocase ascii wide
                        $string2_wifijammer_offensive_tool_keyword = "wifijammer" nocase ascii wide

    condition:
        any of them
}