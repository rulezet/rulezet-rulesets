rule rule_TheFatRat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TheFatRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TheFatRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TheFatRat_offensive_tool_keyword = "/backdoor_apk"
                        $string2_TheFatRat_offensive_tool_keyword = /\/cred_dump\.rc/
                        $string3_TheFatRat_offensive_tool_keyword = "/TheFatRat"

    condition:
        any of them
}