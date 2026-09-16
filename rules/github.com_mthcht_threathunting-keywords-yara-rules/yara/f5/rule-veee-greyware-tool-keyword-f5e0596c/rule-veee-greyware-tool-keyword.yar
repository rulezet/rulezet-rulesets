rule rule_Veee_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Veee' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Veee"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Veee_greyware_tool_keyword = "bnijmipndnicefcdbhgcjoognndbgkep" nocase ascii wide

    condition:
        any of them
}