rule recaptcha_phish
{
    meta:
        description = "Detection patterns for the tool 'recaptcha-phish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "recaptcha-phish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/recaptcha\-phish\.git/ nocase ascii wide
                        $string2 = "/recaptcha-phish-main" nocase ascii wide
                        $string3 = /\\recaptcha\-phish\-main/ nocase ascii wide
                        $string4 = "4f2678fa0f90074ae304f8fdb9174d0c577f1a0587af44a4e8e756a547e5c2e4" nocase ascii wide
                        $string5 = "9593cc106f75cc415faadbeb5b16fa79cfe8c047ad007d50dbf8cb1d242126de" nocase ascii wide
                        $string6 = /const\scommandToRun\s\=\s\\"mshta\s\\"\s\+\shtaPath/ nocase ascii wide
                        $string7 = "I am not a robot - reCAPTCHA Verification ID: 2165" nocase ascii wide
                        $string8 = "I am not a robot - reCAPTCHA Verification ID: 3029" nocase ascii wide
                        $string9 = "I am not a robot - reCAPTCHA Verification ID: 4202" nocase ascii wide
                        $string10 = "I am not a robot - reCAPTCHA Verification ID: 7537" nocase ascii wide
                        $string11 = "I am not a robot - reCAPTCHA Verification ID: 7624" nocase ascii wide
                        $string12 = "I am not a robot - reCAPTCHA Verification ID: 93752" nocase ascii wide
                        $string13 = "JohnHammond/recaptcha-phish" nocase ascii wide
                        $string14 = /mshta.{0,1000}I\sam\snot\sa\srobot\s\-\s.{0,1000}Verification\sID\:\s/ nocase ascii wide
                        $string15 = /mshta\.exe.{0,1000}I\sam\snot\sa\srobot\s\-\sreCAPTCHA\sVerification\sID\:\s/ nocase ascii wide
                        $string16 = /objShell\.Run\s\\"calc\.exe\\"/ nocase ascii wide
                        $string17 = "reCAPTCHA Verification ID: <span id=\"verification-id\">146820</span>" nocase ascii wide
                        $string18 = /recaptcha\-phish\-main\.zip/ nocase ascii wide

    condition:
        any of them
}