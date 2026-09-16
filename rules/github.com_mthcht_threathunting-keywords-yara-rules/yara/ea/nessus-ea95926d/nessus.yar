rule nessus
{
    meta:
        description = "Detection patterns for the tool 'nessus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nessus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/opt/nessus/" nocase ascii wide
                        $string2 = /log4shell.{0,1000}\.nessus\.org/ nocase ascii wide
                        $string3 = /nessus.{0,1000}\s\-\-set\slisten_address\=127\.0\.0\.1/ nocase ascii wide
                        $string4 = /Nessus\-.{0,1000}\.deb/ nocase ascii wide
                        $string5 = /Nessus\-.{0,1000}\.dmg/ nocase ascii wide
                        $string6 = /Nessus\-.{0,1000}\.msi/ nocase ascii wide
                        $string7 = /Nessus\-.{0,1000}\.rpm/ nocase ascii wide
                        $string8 = /Nessus\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string9 = /Nessus\-.{0,1000}\.txz/ nocase ascii wide
                        $string10 = "nessuscli fetch"
                        $string11 = "nessuscli fix"
                        $string12 = /nessus\-updates.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string13 = /plugins\.nessus\.org\./ nocase ascii wide
                        $string14 = "systemctl start nessusd"
                        $string15 = /tenable\.com\/downloads\/nessus/ nocase ascii wide

    condition:
        any of them
}