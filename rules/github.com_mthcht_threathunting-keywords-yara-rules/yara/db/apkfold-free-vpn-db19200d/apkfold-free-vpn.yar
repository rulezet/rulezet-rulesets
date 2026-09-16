rule apkfold_free_vpn
{
    meta:
        description = "Detection patterns for the tool 'apkfold free vpn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "apkfold free vpn"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "jbnmpdkcfkochpanomnkhnafobppmccn" nocase ascii wide

    condition:
        any of them
}