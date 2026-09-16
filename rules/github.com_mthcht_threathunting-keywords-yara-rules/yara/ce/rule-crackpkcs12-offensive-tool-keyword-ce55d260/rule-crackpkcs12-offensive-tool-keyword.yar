rule rule_crackpkcs12_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crackpkcs12' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crackpkcs12"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_crackpkcs12_offensive_tool_keyword = "crackpkcs12" nocase ascii wide

    condition:
        any of them
}