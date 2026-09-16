rule rule_Okta_Password_Sprayer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Okta-Password-Sprayer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Okta-Password-Sprayer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Okta_Password_Sprayer_offensive_tool_keyword = /\/oSpray\.py/
                        $string2_Okta_Password_Sprayer_offensive_tool_keyword = /\\oSpray\.py/ nocase ascii wide
                        $string3_Okta_Password_Sprayer_offensive_tool_keyword = "02024fe8246f659fb6dd07eaf93379e8a8011420d10b83e6bb422b66e53c4292" nocase ascii wide
                        $string4_Okta_Password_Sprayer_offensive_tool_keyword = "Okta-Password-Sprayer" nocase ascii wide

    condition:
        any of them
}