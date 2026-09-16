rule rule_ldeep_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ldeep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldeep"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ldeep_offensive_tool_keyword = " ldeep_dump " nocase ascii wide
                        $string2_ldeep_offensive_tool_keyword = "/ldeep/" nocase ascii wide
                        $string3_ldeep_offensive_tool_keyword = /_dump_users\.lst/ nocase ascii wide
                        $string4_ldeep_offensive_tool_keyword = /cache_activedirectory\.py/ nocase ascii wide
                        $string5_ldeep_offensive_tool_keyword = "ldeep cache " nocase ascii wide
                        $string6_ldeep_offensive_tool_keyword = "ldeep ldap -u " nocase ascii wide
                        $string7_ldeep_offensive_tool_keyword = /ldeep.{0,1000}activedirectory\.py/ nocase ascii wide
                        $string8_ldeep_offensive_tool_keyword = /ldeep.{0,1000}ldap_activedirectory\.py/ nocase ascii wide
                        $string9_ldeep_offensive_tool_keyword = /ldeep_dump_users_enabled\.json/ nocase ascii wide
                        $string10_ldeep_offensive_tool_keyword = /ldeep_dump_users_enabled\.lst/ nocase ascii wide

    condition:
        any of them
}