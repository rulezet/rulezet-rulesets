rule whiskeysamlandfriends
{
    meta:
        description = "Detection patterns for the tool 'whiskeysamlandfriends' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whiskeysamlandfriends"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-adfs\-host\s.{0,1000}\s\-\-krb\-key\s.{0,1000}\s\-\-krb\-ticket\s/ nocase ascii wide
                        $string2 = /\s\-\-target\-user\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-command\s/ nocase ascii wide
                        $string3 = /\sticketsplease\./ nocase ascii wide
                        $string4 = "/shocknawe/" nocase ascii wide
                        $string5 = /\/ticketer\.py/ nocase ascii wide
                        $string6 = /\/ticketsplease\.py/ nocase ascii wide
                        $string7 = /ADFSpoof\.py/ nocase ascii wide
                        $string8 = /dcsync\.py/ nocase ascii wide
                        $string9 = "generate_golden_saml" nocase ascii wide
                        $string10 = "import DCSYNC" nocase ascii wide
                        $string11 = /shocknawe\.py/ nocase ascii wide
                        $string12 = /smb\.dcsync/ nocase ascii wide
                        $string13 = "ticketsplease adfs " nocase ascii wide
                        $string14 = "ticketsplease azure " nocase ascii wide
                        $string15 = "ticketsplease dcsync " nocase ascii wide
                        $string16 = "ticketsplease ldap " nocase ascii wide
                        $string17 = "ticketsplease saml " nocase ascii wide
                        $string18 = "ticketsplease ticket --domain" nocase ascii wide
                        $string19 = /ticketsplease\.modules\./ nocase ascii wide
                        $string20 = /whiskeysaml\.py/ nocase ascii wide
                        $string21 = "whiskeysamlandfriends" nocase ascii wide

    condition:
        any of them
}