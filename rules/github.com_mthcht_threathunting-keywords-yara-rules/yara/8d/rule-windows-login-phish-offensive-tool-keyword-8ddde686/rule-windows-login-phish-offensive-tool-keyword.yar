rule rule_windows_login_phish_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'windows-login-phish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-login-phish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_windows_login_phish_offensive_tool_keyword = "/windows-login-phish" nocase ascii wide
                        $string2_windows_login_phish_offensive_tool_keyword = /AttackerSetup\(windows\)\.exe/ nocase ascii wide
                        $string3_windows_login_phish_offensive_tool_keyword = /AttackerSetup\.py/ nocase ascii wide
                        $string4_windows_login_phish_offensive_tool_keyword = "AttackerSetup4linux"

    condition:
        any of them
}