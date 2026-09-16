rule rule_ratchatgpt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ratchatgpt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatgpt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ratchatgpt_offensive_tool_keyword = "/output/ratchatPT" nocase ascii wide
                        $string2_ratchatgpt_offensive_tool_keyword = /\/ratchatpt\.git/ nocase ascii wide
                        $string3_ratchatgpt_offensive_tool_keyword = /\/ratchatPT\.go/ nocase ascii wide
                        $string4_ratchatgpt_offensive_tool_keyword = /\/ratchatPT\.syso/ nocase ascii wide
                        $string5_ratchatgpt_offensive_tool_keyword = /\\rpt_win\.exe/ nocase ascii wide
                        $string6_ratchatgpt_offensive_tool_keyword = /RatChatPT\.exe/ nocase ascii wide
                        $string7_ratchatgpt_offensive_tool_keyword = /RatChatPT_windows\.exe/ nocase ascii wide
                        $string8_ratchatgpt_offensive_tool_keyword = "ratchatpt-main" nocase ascii wide
                        $string9_ratchatgpt_offensive_tool_keyword = "spartan-conseil/ratchatpt" nocase ascii wide

    condition:
        any of them
}