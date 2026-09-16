rule Veee
{
    meta:
        description = "Detection patterns for the tool 'Veee' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Veee"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bnijmipndnicefcdbhgcjoognndbgkep" nocase ascii wide

    condition:
        any of them
}