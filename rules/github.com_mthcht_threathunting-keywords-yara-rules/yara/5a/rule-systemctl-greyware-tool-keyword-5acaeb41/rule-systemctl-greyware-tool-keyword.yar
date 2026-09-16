rule rule_systemctl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'systemctl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "systemctl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_systemctl_greyware_tool_keyword = "systemctl disable cbdaemon" nocase ascii wide
                        $string2_systemctl_greyware_tool_keyword = /systemctl\sdisable\sfalcon\-sensor\.service/ nocase ascii wide
                        $string3_systemctl_greyware_tool_keyword = "systemctl stop cbdaemon" nocase ascii wide
                        $string4_systemctl_greyware_tool_keyword = /systemctl\sstop\sfalcon\-sensor\.service/ nocase ascii wide
                        $string5_systemctl_greyware_tool_keyword = /systemctl\sstop\susbguard\.service/ nocase ascii wide

    condition:
        any of them
}