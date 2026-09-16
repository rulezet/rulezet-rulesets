rule sshuttle
{
    meta:
        description = "Detection patterns for the tool 'sshuttle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshuttle"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " install sshuttle"
                        $string2 = " py39-sshuttle"
                        $string3 = " sshuttle:sshuttle "
                        $string4 = "/etc/sshuttle"
                        $string5 = "/home/sshuttle"
                        $string6 = /\/sshuttle\.git/
                        $string7 = /\/sshuttle\.py/
                        $string8 = "/sshuttle/tarball"
                        $string9 = "/sshuttle/zipball"
                        $string10 = "/tmp/sshuttle"
                        $string11 = "b86e9468c1470e3a3e776f5cab91a1cb79927743cfbc92535e753024611e8b4e" nocase ascii wide
                        $string12 = "net-proxy/sshuttle"
                        $string13 = "sshuttle -"
                        $string14 = /sshuttle\.cmdline/
                        $string15 = /sshuttle\.firewall/
                        $string16 = /sshuttle\.linux/
                        $string17 = /sshuttle\.methods\.socket/
                        $string18 = /sshuttle\.server/
                        $string19 = /sshuttle\.service/
                        $string20 = /sshuttle\.ssh/
                        $string21 = "sshuttle/sshuttle"
                        $string22 = "SSHUTTLE0001"
                        $string23 = /sudoers\.d\/sshuttle_auto/
                        $string24 = "systemctl start sshuttle"

    condition:
        any of them
}