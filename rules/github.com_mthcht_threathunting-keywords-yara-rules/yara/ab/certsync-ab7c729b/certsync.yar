rule certsync
{
    meta:
        description = "Detection patterns for the tool 'certsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certsync"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/certsync\.git/ nocase ascii wide
                        $string2 = /\\certipy\.pfx/ nocase ascii wide
                        $string3 = /\\Windows\\Tasks\\Certipy/ nocase ascii wide
                        $string4 = /certsync\s.{0,1000}\-\-dc\-ip/ nocase ascii wide
                        $string5 = "certsync -u " nocase ascii wide
                        $string6 = /certsync\-master\.zip/ nocase ascii wide
                        $string7 = "install certsync" nocase ascii wide
                        $string8 = "zblurx/certsync" nocase ascii wide

    condition:
        any of them
}