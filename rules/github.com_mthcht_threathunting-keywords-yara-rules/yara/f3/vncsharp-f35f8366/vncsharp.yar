rule VncSharp
{
    meta:
        description = "Detection patterns for the tool 'VncSharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VncSharp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/VncSharp\.exe/ nocase ascii wide
                        $string2 = /\/VncSharp\.git/ nocase ascii wide
                        $string3 = /\\VncSharp\.exe/ nocase ascii wide
                        $string4 = /\\VncSharp\.sln/ nocase ascii wide
                        $string5 = "73e83646-1d53-4dec-950a-a48559e438e8" nocase ascii wide
                        $string6 = "dfedf8e6a6cdb480ee00545da5e7d5370b5b7057d0b274f3a6f9cf4a192a87e6" nocase ascii wide
                        $string7 = "E0695F0F-0FAF-44BC-AE55-A1FCBFE70271" nocase ascii wide
                        $string8 = "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683" nocase ascii wide
                        $string9 = "humphd/VncSharp" nocase ascii wide

    condition:
        any of them
}