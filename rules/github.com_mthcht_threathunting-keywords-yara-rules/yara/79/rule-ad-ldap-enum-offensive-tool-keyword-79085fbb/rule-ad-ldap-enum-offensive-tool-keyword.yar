rule rule_ad_ldap_enum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ad-ldap-enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ad-ldap-enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ad_ldap_enum_offensive_tool_keyword = " -p 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'" nocase ascii wide
                        $string2_ad_ldap_enum_offensive_tool_keyword = /\/ad\-ldap\-enum\.git/ nocase ascii wide
                        $string3_ad_ldap_enum_offensive_tool_keyword = /ad\-ldap\-enum\.py/ nocase ascii wide
                        $string4_ad_ldap_enum_offensive_tool_keyword = "ad-ldap-enum-main" nocase ascii wide
                        $string5_ad_ldap_enum_offensive_tool_keyword = "CroweCybersecurity/ad-ldap-enum" nocase ascii wide

    condition:
        any of them
}