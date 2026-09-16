rule Red_Panda_VPN
{
    meta:
        description = "Detection patterns for the tool 'Red Panda VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Red Panda VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "plpmggfglncceinmilojdkiijhmajkjh" nocase ascii wide

    condition:
        any of them
}