rule windows_login_phish
{
    meta:
        description = "Detection patterns for the tool 'windows-login-phish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-login-phish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/windows-login-phish" nocase ascii wide
                        $string2 = /AttackerSetup\(windows\)\.exe/ nocase ascii wide
                        $string3 = /AttackerSetup\.py/ nocase ascii wide
                        $string4 = "AttackerSetup4linux"

    condition:
        any of them
}