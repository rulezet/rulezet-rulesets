rule rule_Admin2Sys_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Admin2Sys' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Admin2Sys"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Admin2Sys_offensive_tool_keyword = /\/Admin2Sys\.git/ nocase ascii wide
                        $string2_Admin2Sys_offensive_tool_keyword = /Admin2Sys\.exe/ nocase ascii wide
                        $string3_Admin2Sys_offensive_tool_keyword = "Admin2Sys-main" nocase ascii wide
                        $string4_Admin2Sys_offensive_tool_keyword = "S12cybersecurity/Admin2Sys" nocase ascii wide

    condition:
        any of them
}