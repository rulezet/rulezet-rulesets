rule ldeep
{
    meta:
        description = "Detection patterns for the tool 'ldeep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldeep"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " ldeep_dump " nocase ascii wide
                        $string2 = "/ldeep/" nocase ascii wide
                        $string3 = /_dump_users\.lst/ nocase ascii wide
                        $string4 = /cache_activedirectory\.py/ nocase ascii wide
                        $string5 = "ldeep cache " nocase ascii wide
                        $string6 = "ldeep ldap -u " nocase ascii wide
                        $string7 = /ldeep.{0,1000}activedirectory\.py/ nocase ascii wide
                        $string8 = /ldeep.{0,1000}ldap_activedirectory\.py/ nocase ascii wide
                        $string9 = /ldeep_dump_users_enabled\.json/ nocase ascii wide
                        $string10 = /ldeep_dump_users_enabled\.lst/ nocase ascii wide

    condition:
        any of them
}