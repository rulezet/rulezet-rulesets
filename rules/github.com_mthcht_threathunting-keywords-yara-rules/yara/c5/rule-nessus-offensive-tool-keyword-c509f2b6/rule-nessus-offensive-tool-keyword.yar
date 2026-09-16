rule rule_nessus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nessus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nessus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nessus_offensive_tool_keyword = "/opt/nessus/" nocase ascii wide
                        $string2_nessus_offensive_tool_keyword = /log4shell.{0,1000}\.nessus\.org/ nocase ascii wide
                        $string3_nessus_offensive_tool_keyword = /nessus.{0,1000}\s\-\-set\slisten_address\=127\.0\.0\.1/ nocase ascii wide
                        $string4_nessus_offensive_tool_keyword = /Nessus\-.{0,1000}\.deb/ nocase ascii wide
                        $string5_nessus_offensive_tool_keyword = /Nessus\-.{0,1000}\.dmg/ nocase ascii wide
                        $string6_nessus_offensive_tool_keyword = /Nessus\-.{0,1000}\.msi/ nocase ascii wide
                        $string7_nessus_offensive_tool_keyword = /Nessus\-.{0,1000}\.rpm/ nocase ascii wide
                        $string8_nessus_offensive_tool_keyword = /Nessus\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string9_nessus_offensive_tool_keyword = /Nessus\-.{0,1000}\.txz/ nocase ascii wide
                        $string10_nessus_offensive_tool_keyword = "nessuscli fetch"
                        $string11_nessus_offensive_tool_keyword = "nessuscli fix"
                        $string12_nessus_offensive_tool_keyword = /nessus\-updates.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string13_nessus_offensive_tool_keyword = /plugins\.nessus\.org\./ nocase ascii wide
                        $string14_nessus_offensive_tool_keyword = "systemctl start nessusd"
                        $string15_nessus_offensive_tool_keyword = /tenable\.com\/downloads\/nessus/ nocase ascii wide

    condition:
        any of them
}