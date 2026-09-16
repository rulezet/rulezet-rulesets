rule FREE_VPN_DEWELOPMENT
{
    meta:
        description = "Detection patterns for the tool 'FREE VPN DEWELOPMENT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FREE VPN DEWELOPMENT"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ifnaibldjfdmaipaddffmgcmekjhiloa" nocase ascii wide

    condition:
        any of them
}