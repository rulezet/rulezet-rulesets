rule ExtPassword_exe
{
    meta:
        description = "Detection patterns for the tool 'ExtPassword.exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtPassword.exe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/extpassword\.zip/ nocase ascii wide
                        $string2 = /\/utils\/external_drive_password_recovery\.html/ nocase ascii wide
                        $string3 = /\\ExtPassword\.chm/ nocase ascii wide
                        $string4 = /\\ExtPassword\.html/ nocase ascii wide
                        $string5 = /\\extpassword\.zip/ nocase ascii wide
                        $string6 = /\\ExtPassword_lng\.ini/ nocase ascii wide
                        $string7 = "03a544b51ade8258a377800fda3237ce6f36ebae34e6787380c0a2f341b591e9" nocase ascii wide
                        $string8 = "bd61c5daaad30b420817fb1fd2f0447c3b66a1900ba69fd4cd724d1e6897ab41" nocase ascii wide
                        $string9 = "External Drive Password Recovery" nocase ascii wide
                        $string10 = /ExtPassword\.exe/ nocase ascii wide

    condition:
        any of them
}