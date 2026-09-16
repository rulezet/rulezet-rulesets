rule rule_emkei_cz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'emkei.cz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "emkei.cz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_emkei_cz_offensive_tool_keyword = /https\:\/\/emkei\.cz\// nocase ascii wide

    condition:
        any of them
}