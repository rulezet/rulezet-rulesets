rule sVPN
{
    meta:
        description = "Detection patterns for the tool 'sVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "iocnglnmfkgfedpcemdflhkchokkfeii" nocase ascii wide

    condition:
        any of them
}