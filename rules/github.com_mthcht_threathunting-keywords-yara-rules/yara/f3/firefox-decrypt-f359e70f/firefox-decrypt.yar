rule firefox_decrypt
{
    meta:
        description = "Detection patterns for the tool 'firefox_decrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "firefox_decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/firefox_decrypt\.git/ nocase ascii wide
                        $string2 = /firefox_decrypt\.py/ nocase ascii wide
                        $string3 = "firefox_decrypt-main" nocase ascii wide
                        $string4 = "unode/firefox_decrypt" nocase ascii wide

    condition:
        any of them
}