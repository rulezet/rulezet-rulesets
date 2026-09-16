rule Admin2Sys
{
    meta:
        description = "Detection patterns for the tool 'Admin2Sys' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Admin2Sys"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Admin2Sys\.git/ nocase ascii wide
                        $string2 = /Admin2Sys\.exe/ nocase ascii wide
                        $string3 = "Admin2Sys-main" nocase ascii wide
                        $string4 = "S12cybersecurity/Admin2Sys" nocase ascii wide

    condition:
        any of them
}