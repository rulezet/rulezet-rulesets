rule rule_SharpDomainSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpDomainSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDomainSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpDomainSpray_offensive_tool_keyword = /\/SharpDomainSpray\.git/ nocase ascii wide
                        $string2_SharpDomainSpray_offensive_tool_keyword = /\/SharpSpray\.exe/ nocase ascii wide
                        $string3_SharpDomainSpray_offensive_tool_keyword = /\\SharpDomainSpraty\\/ nocase ascii wide
                        $string4_SharpDomainSpray_offensive_tool_keyword = /\\SharpSpray\.exe/ nocase ascii wide
                        $string5_SharpDomainSpray_offensive_tool_keyword = "76FFA92B-429B-4865-970D-4E7678AC34EA" nocase ascii wide
                        $string6_SharpDomainSpray_offensive_tool_keyword = "HunnicCyber/SharpDomainSpray" nocase ascii wide
                        $string7_SharpDomainSpray_offensive_tool_keyword = "Perform password spraying for all active users on a domain" nocase ascii wide
                        $string8_SharpDomainSpray_offensive_tool_keyword = "SharpDomainSpray" nocase ascii wide
                        $string9_SharpDomainSpray_offensive_tool_keyword = /SharpDomainSpray\./ nocase ascii wide
                        $string10_SharpDomainSpray_offensive_tool_keyword = "SharpDomainSpray-master" nocase ascii wide
                        $string11_SharpDomainSpray_offensive_tool_keyword = /SharpSpray\.exe\s/ nocase ascii wide

    condition:
        any of them
}