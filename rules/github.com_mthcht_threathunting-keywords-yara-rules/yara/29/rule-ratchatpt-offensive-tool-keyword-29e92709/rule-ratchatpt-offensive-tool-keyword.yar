rule rule_ratchatpt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ratchatpt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatpt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ratchatpt_offensive_tool_keyword = /\/ratchatpt\.git/ nocase ascii wide
                        $string2_ratchatpt_offensive_tool_keyword = /\/ratchatPT\.go/ nocase ascii wide
                        $string3_ratchatpt_offensive_tool_keyword = /\/ratchatPT\.syso/ nocase ascii wide
                        $string4_ratchatpt_offensive_tool_keyword = "/root/output/ratchatPT"
                        $string5_ratchatpt_offensive_tool_keyword = /\\ratchatPT\.go/ nocase ascii wide
                        $string6_ratchatpt_offensive_tool_keyword = /\\ratchatPT\.syso/ nocase ascii wide
                        $string7_ratchatpt_offensive_tool_keyword = /Agent\/ratchatPT\.go/ nocase ascii wide
                        $string8_ratchatpt_offensive_tool_keyword = "output/RatChatPT_unix" nocase ascii wide
                        $string9_ratchatpt_offensive_tool_keyword = /ratchatPT.{0,1000}\/bin\/bash/
                        $string10_ratchatpt_offensive_tool_keyword = /RatChatPT\.exe/ nocase ascii wide
                        $string11_ratchatpt_offensive_tool_keyword = /RatChatPT_windows\.exe/ nocase ascii wide
                        $string12_ratchatpt_offensive_tool_keyword = "ratchatpt-main" nocase ascii wide
                        $string13_ratchatpt_offensive_tool_keyword = "spartan-conseil/ratchatpt" nocase ascii wide

    condition:
        any of them
}