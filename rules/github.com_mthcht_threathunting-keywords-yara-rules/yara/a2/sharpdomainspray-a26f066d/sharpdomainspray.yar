rule SharpDomainSpray
{
    meta:
        description = "Detection patterns for the tool 'SharpDomainSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDomainSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpDomainSpray\.git/ nocase ascii wide
                        $string2 = /\/SharpSpray\.exe/ nocase ascii wide
                        $string3 = /\\SharpDomainSpraty\\/ nocase ascii wide
                        $string4 = /\\SharpSpray\.exe/ nocase ascii wide
                        $string5 = "76FFA92B-429B-4865-970D-4E7678AC34EA" nocase ascii wide
                        $string6 = "HunnicCyber/SharpDomainSpray" nocase ascii wide
                        $string7 = "Perform password spraying for all active users on a domain" nocase ascii wide
                        $string8 = "SharpDomainSpray" nocase ascii wide
                        $string9 = /SharpDomainSpray\./ nocase ascii wide
                        $string10 = "SharpDomainSpray-master" nocase ascii wide
                        $string11 = /SharpSpray\.exe\s/ nocase ascii wide

    condition:
        any of them
}