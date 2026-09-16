rule Okta_Password_Sprayer
{
    meta:
        description = "Detection patterns for the tool 'Okta-Password-Sprayer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Okta-Password-Sprayer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/oSpray\.py/
                        $string2 = /\\oSpray\.py/ nocase ascii wide
                        $string3 = "02024fe8246f659fb6dd07eaf93379e8a8011420d10b83e6bb422b66e53c4292" nocase ascii wide
                        $string4 = "Okta-Password-Sprayer" nocase ascii wide

    condition:
        any of them
}