rule rule_Browser_password_stealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browser-password-stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-password-stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Browser_password_stealer_offensive_tool_keyword = /\schromium_based_browsers\.py/ nocase ascii wide
                        $string2_Browser_password_stealer_offensive_tool_keyword = /\/chromium_based_browsers\.py/ nocase ascii wide
                        $string3_Browser_password_stealer_offensive_tool_keyword = /\\chromium_based_browsers\.py/ nocase ascii wide
                        $string4_Browser_password_stealer_offensive_tool_keyword = /Browser\-password\-stealer\.git/ nocase ascii wide
                        $string5_Browser_password_stealer_offensive_tool_keyword = "Browser-password-stealer-master" nocase ascii wide
                        $string6_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/cookies\.txt/ nocase ascii wide
                        $string7_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/credit_cards\.txt/ nocase ascii wide
                        $string8_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/history\.txt/ nocase ascii wide
                        $string9_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\/login_data\.txt/ nocase ascii wide
                        $string10_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\cookies\.txt/ nocase ascii wide
                        $string11_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\credit_cards\.txt/ nocase ascii wide
                        $string12_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\history\.txt/ nocase ascii wide
                        $string13_Browser_password_stealer_offensive_tool_keyword = /google\-chrome\\login_data\.txt/ nocase ascii wide
                        $string14_Browser_password_stealer_offensive_tool_keyword = "henry-richard7/Browser-password-stealer" nocase ascii wide
                        $string15_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/cookies\.txt/ nocase ascii wide
                        $string16_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/credit_cards\.txt/ nocase ascii wide
                        $string17_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/history\.txt/ nocase ascii wide
                        $string18_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\/login_data\.txt/ nocase ascii wide
                        $string19_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\cookies\.txt/ nocase ascii wide
                        $string20_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\credit_cards\.txt/ nocase ascii wide
                        $string21_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\history\.txt/ nocase ascii wide
                        $string22_Browser_password_stealer_offensive_tool_keyword = /microsoft\-edge\\login_data\.txt/ nocase ascii wide

    condition:
        any of them
}