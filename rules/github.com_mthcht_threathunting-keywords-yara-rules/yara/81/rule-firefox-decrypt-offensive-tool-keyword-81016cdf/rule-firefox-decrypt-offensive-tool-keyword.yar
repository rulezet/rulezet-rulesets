rule rule_firefox_decrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'firefox_decrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "firefox_decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_firefox_decrypt_offensive_tool_keyword = /\/firefox_decrypt\.git/ nocase ascii wide
                        $string2_firefox_decrypt_offensive_tool_keyword = /firefox_decrypt\.py/ nocase ascii wide
                        $string3_firefox_decrypt_offensive_tool_keyword = "firefox_decrypt-main" nocase ascii wide
                        $string4_firefox_decrypt_offensive_tool_keyword = "unode/firefox_decrypt" nocase ascii wide

    condition:
        any of them
}