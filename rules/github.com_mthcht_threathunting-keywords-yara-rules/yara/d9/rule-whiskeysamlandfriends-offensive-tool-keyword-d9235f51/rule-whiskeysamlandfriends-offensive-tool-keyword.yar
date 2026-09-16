rule rule_whiskeysamlandfriends_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'whiskeysamlandfriends' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whiskeysamlandfriends"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_whiskeysamlandfriends_offensive_tool_keyword = /\s\-\-adfs\-host\s.{0,1000}\s\-\-krb\-key\s.{0,1000}\s\-\-krb\-ticket\s/ nocase ascii wide
                        $string2_whiskeysamlandfriends_offensive_tool_keyword = /\s\-\-target\-user\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-command\s/ nocase ascii wide
                        $string3_whiskeysamlandfriends_offensive_tool_keyword = /\sticketsplease\./ nocase ascii wide
                        $string4_whiskeysamlandfriends_offensive_tool_keyword = "/shocknawe/" nocase ascii wide
                        $string5_whiskeysamlandfriends_offensive_tool_keyword = /\/ticketer\.py/ nocase ascii wide
                        $string6_whiskeysamlandfriends_offensive_tool_keyword = /\/ticketsplease\.py/ nocase ascii wide
                        $string7_whiskeysamlandfriends_offensive_tool_keyword = /ADFSpoof\.py/ nocase ascii wide
                        $string8_whiskeysamlandfriends_offensive_tool_keyword = /dcsync\.py/ nocase ascii wide
                        $string9_whiskeysamlandfriends_offensive_tool_keyword = "generate_golden_saml" nocase ascii wide
                        $string10_whiskeysamlandfriends_offensive_tool_keyword = "import DCSYNC" nocase ascii wide
                        $string11_whiskeysamlandfriends_offensive_tool_keyword = /shocknawe\.py/ nocase ascii wide
                        $string12_whiskeysamlandfriends_offensive_tool_keyword = /smb\.dcsync/ nocase ascii wide
                        $string13_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease adfs " nocase ascii wide
                        $string14_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease azure " nocase ascii wide
                        $string15_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease dcsync " nocase ascii wide
                        $string16_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease ldap " nocase ascii wide
                        $string17_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease saml " nocase ascii wide
                        $string18_whiskeysamlandfriends_offensive_tool_keyword = "ticketsplease ticket --domain" nocase ascii wide
                        $string19_whiskeysamlandfriends_offensive_tool_keyword = /ticketsplease\.modules\./ nocase ascii wide
                        $string20_whiskeysamlandfriends_offensive_tool_keyword = /whiskeysaml\.py/ nocase ascii wide
                        $string21_whiskeysamlandfriends_offensive_tool_keyword = "whiskeysamlandfriends" nocase ascii wide

    condition:
        any of them
}