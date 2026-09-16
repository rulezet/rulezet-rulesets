rule rule_ExtPassword_exe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ExtPassword.exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtPassword.exe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ExtPassword_exe_offensive_tool_keyword = /\/extpassword\.zip/ nocase ascii wide
                        $string2_ExtPassword_exe_offensive_tool_keyword = /\/utils\/external_drive_password_recovery\.html/ nocase ascii wide
                        $string3_ExtPassword_exe_offensive_tool_keyword = /\\ExtPassword\.chm/ nocase ascii wide
                        $string4_ExtPassword_exe_offensive_tool_keyword = /\\ExtPassword\.html/ nocase ascii wide
                        $string5_ExtPassword_exe_offensive_tool_keyword = /\\extpassword\.zip/ nocase ascii wide
                        $string6_ExtPassword_exe_offensive_tool_keyword = /\\ExtPassword_lng\.ini/ nocase ascii wide
                        $string7_ExtPassword_exe_offensive_tool_keyword = "03a544b51ade8258a377800fda3237ce6f36ebae34e6787380c0a2f341b591e9" nocase ascii wide
                        $string8_ExtPassword_exe_offensive_tool_keyword = "bd61c5daaad30b420817fb1fd2f0447c3b66a1900ba69fd4cd724d1e6897ab41" nocase ascii wide
                        $string9_ExtPassword_exe_offensive_tool_keyword = "External Drive Password Recovery" nocase ascii wide
                        $string10_ExtPassword_exe_offensive_tool_keyword = /ExtPassword\.exe/ nocase ascii wide

    condition:
        any of them
}