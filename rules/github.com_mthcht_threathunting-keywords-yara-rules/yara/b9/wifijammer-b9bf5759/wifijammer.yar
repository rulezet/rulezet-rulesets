rule wifijammer
{
    meta:
        description = "Detection patterns for the tool 'wifijammer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifijammer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "hash3liZer/wifijammer" nocase ascii wide
                        $string2 = "wifijammer" nocase ascii wide

    condition:
        any of them
}