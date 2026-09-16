rule rule_PWA_Phishing_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PWA-Phishing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWA-Phishing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PWA_Phishing_offensive_tool_keyword = /\/mrd0x\.html/ nocase ascii wide
                        $string2_PWA_Phishing_offensive_tool_keyword = /\/PWA\-Phishing\.git/ nocase ascii wide
                        $string3_PWA_Phishing_offensive_tool_keyword = /\\PWA\-Phishing/ nocase ascii wide
                        $string4_PWA_Phishing_offensive_tool_keyword = "18c54c69f41d0b7e5928c34e1e9350ed99ecd0278ea37df11a429018ca3d05ed" nocase ascii wide
                        $string5_PWA_Phishing_offensive_tool_keyword = "3b1e2b01bfa6ad0deefa3bf8e7a81e9fc295e56b8f087ef402d9a06e42ec3b95" nocase ascii wide
                        $string6_PWA_Phishing_offensive_tool_keyword = "95b9a6d12b978a6c1bbd6a33369e39008e7d64544d50c98c9c3f2b93a9466e79" nocase ascii wide
                        $string7_PWA_Phishing_offensive_tool_keyword = "bfa9dc4c4b911b6777cb98d17a82b28531c26600698699cbe658749684818f28" nocase ascii wide
                        $string8_PWA_Phishing_offensive_tool_keyword = /fopen\(\'credentials\.txt\'/ nocase ascii wide
                        $string9_PWA_Phishing_offensive_tool_keyword = /https\:\/\/mrd0x\.com\/progressive\-web\-apps\-pwa\-phishing/ nocase ascii wide
                        $string10_PWA_Phishing_offensive_tool_keyword = "mrd0x/PWA-Phishing" nocase ascii wide

    condition:
        any of them
}