rule Browser_password_stealer
{
    meta:
        description = "Detection patterns for the tool 'Browser-password-stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-password-stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\schromium_based_browsers\.py/ nocase ascii wide
                        $string2 = /\/chromium_based_browsers\.py/ nocase ascii wide
                        $string3 = /\\chromium_based_browsers\.py/ nocase ascii wide
                        $string4 = /Browser\-password\-stealer\.git/ nocase ascii wide
                        $string5 = "Browser-password-stealer-master" nocase ascii wide
                        $string6 = /google\-chrome\/cookies\.txt/ nocase ascii wide
                        $string7 = /google\-chrome\/credit_cards\.txt/ nocase ascii wide
                        $string8 = /google\-chrome\/history\.txt/ nocase ascii wide
                        $string9 = /google\-chrome\/login_data\.txt/ nocase ascii wide
                        $string10 = /google\-chrome\\cookies\.txt/ nocase ascii wide
                        $string11 = /google\-chrome\\credit_cards\.txt/ nocase ascii wide
                        $string12 = /google\-chrome\\history\.txt/ nocase ascii wide
                        $string13 = /google\-chrome\\login_data\.txt/ nocase ascii wide
                        $string14 = "henry-richard7/Browser-password-stealer" nocase ascii wide
                        $string15 = /microsoft\-edge\/cookies\.txt/ nocase ascii wide
                        $string16 = /microsoft\-edge\/credit_cards\.txt/ nocase ascii wide
                        $string17 = /microsoft\-edge\/history\.txt/ nocase ascii wide
                        $string18 = /microsoft\-edge\/login_data\.txt/ nocase ascii wide
                        $string19 = /microsoft\-edge\\cookies\.txt/ nocase ascii wide
                        $string20 = /microsoft\-edge\\credit_cards\.txt/ nocase ascii wide
                        $string21 = /microsoft\-edge\\history\.txt/ nocase ascii wide
                        $string22 = /microsoft\-edge\\login_data\.txt/ nocase ascii wide

    condition:
        any of them
}