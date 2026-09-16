rule systemctl
{
    meta:
        description = "Detection patterns for the tool 'systemctl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "systemctl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "systemctl disable cbdaemon" nocase ascii wide
                        $string2 = /systemctl\sdisable\sfalcon\-sensor\.service/ nocase ascii wide
                        $string3 = "systemctl stop cbdaemon" nocase ascii wide
                        $string4 = /systemctl\sstop\sfalcon\-sensor\.service/ nocase ascii wide
                        $string5 = /systemctl\sstop\susbguard\.service/ nocase ascii wide

    condition:
        any of them
}