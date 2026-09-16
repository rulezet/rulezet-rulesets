rule ratchatgpt
{
    meta:
        description = "Detection patterns for the tool 'ratchatgpt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatgpt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/output/ratchatPT" nocase ascii wide
                        $string2 = /\/ratchatpt\.git/ nocase ascii wide
                        $string3 = /\/ratchatPT\.go/ nocase ascii wide
                        $string4 = /\/ratchatPT\.syso/ nocase ascii wide
                        $string5 = /\\rpt_win\.exe/ nocase ascii wide
                        $string6 = /RatChatPT\.exe/ nocase ascii wide
                        $string7 = /RatChatPT_windows\.exe/ nocase ascii wide
                        $string8 = "ratchatpt-main" nocase ascii wide
                        $string9 = "spartan-conseil/ratchatpt" nocase ascii wide

    condition:
        any of them
}