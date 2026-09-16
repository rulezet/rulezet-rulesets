rule PureVPN
{
    meta:
        description = "Detection patterns for the tool 'PureVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PureVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bfidboloedlamgdmenmlbipfnccokknp" nocase ascii wide

    condition:
        any of them
}