rule ratchatpt
{
    meta:
        description = "Detection patterns for the tool 'ratchatpt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatpt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ratchatpt\.git/ nocase ascii wide
                        $string2 = /\/ratchatPT\.go/ nocase ascii wide
                        $string3 = /\/ratchatPT\.syso/ nocase ascii wide
                        $string4 = "/root/output/ratchatPT"
                        $string5 = /\\ratchatPT\.go/ nocase ascii wide
                        $string6 = /\\ratchatPT\.syso/ nocase ascii wide
                        $string7 = /Agent\/ratchatPT\.go/ nocase ascii wide
                        $string8 = "output/RatChatPT_unix" nocase ascii wide
                        $string9 = /ratchatPT.{0,1000}\/bin\/bash/
                        $string10 = /RatChatPT\.exe/ nocase ascii wide
                        $string11 = /RatChatPT_windows\.exe/ nocase ascii wide
                        $string12 = "ratchatpt-main" nocase ascii wide
                        $string13 = "spartan-conseil/ratchatpt" nocase ascii wide

    condition:
        any of them
}