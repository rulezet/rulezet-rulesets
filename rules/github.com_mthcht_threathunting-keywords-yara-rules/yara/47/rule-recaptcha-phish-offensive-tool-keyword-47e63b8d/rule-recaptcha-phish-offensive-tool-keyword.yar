rule rule_recaptcha_phish_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'recaptcha-phish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "recaptcha-phish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_recaptcha_phish_offensive_tool_keyword = /\/recaptcha\-phish\.git/ nocase ascii wide
                        $string2_recaptcha_phish_offensive_tool_keyword = "/recaptcha-phish-main" nocase ascii wide
                        $string3_recaptcha_phish_offensive_tool_keyword = /\\recaptcha\-phish\-main/ nocase ascii wide
                        $string4_recaptcha_phish_offensive_tool_keyword = "4f2678fa0f90074ae304f8fdb9174d0c577f1a0587af44a4e8e756a547e5c2e4" nocase ascii wide
                        $string5_recaptcha_phish_offensive_tool_keyword = "9593cc106f75cc415faadbeb5b16fa79cfe8c047ad007d50dbf8cb1d242126de" nocase ascii wide
                        $string6_recaptcha_phish_offensive_tool_keyword = /const\scommandToRun\s\=\s\\"mshta\s\\"\s\+\shtaPath/ nocase ascii wide
                        $string7_recaptcha_phish_offensive_tool_keyword = "I am not a robot - reCAPTCHA Verification ID: 2165" nocase ascii wide
                        $string8_recaptcha_phish_offensive_tool_keyword = "I am not a robot - reCAPTCHA Verification ID: 3029" nocase ascii wide
                        $string9_recaptcha_phish_offensive_tool_keyword = "I am not a robot - reCAPTCHA Verification ID: 4202" nocase ascii wide
                        $string10_recaptcha_phish_offensive_tool_keyword = "I am not a robot - reCAPTCHA Verification ID: 7537" nocase ascii wide
                        $string11_recaptcha_phish_offensive_tool_keyword = "I am not a robot - reCAPTCHA Verification ID: 7624" nocase ascii wide
                        $string12_recaptcha_phish_offensive_tool_keyword = "I am not a robot - reCAPTCHA Verification ID: 93752" nocase ascii wide
                        $string13_recaptcha_phish_offensive_tool_keyword = "JohnHammond/recaptcha-phish" nocase ascii wide
                        $string14_recaptcha_phish_offensive_tool_keyword = /mshta.{0,1000}I\sam\snot\sa\srobot\s\-\s.{0,1000}Verification\sID\:\s/ nocase ascii wide
                        $string15_recaptcha_phish_offensive_tool_keyword = /mshta\.exe.{0,1000}I\sam\snot\sa\srobot\s\-\sreCAPTCHA\sVerification\sID\:\s/ nocase ascii wide
                        $string16_recaptcha_phish_offensive_tool_keyword = /objShell\.Run\s\\"calc\.exe\\"/ nocase ascii wide
                        $string17_recaptcha_phish_offensive_tool_keyword = "reCAPTCHA Verification ID: <span id=\"verification-id\">146820</span>" nocase ascii wide
                        $string18_recaptcha_phish_offensive_tool_keyword = /recaptcha\-phish\-main\.zip/ nocase ascii wide

    condition:
        any of them
}