rule rule_VncSharp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VncSharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VncSharp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_VncSharp_greyware_tool_keyword = /\/VncSharp\.exe/ nocase ascii wide
                        $string2_VncSharp_greyware_tool_keyword = /\/VncSharp\.git/ nocase ascii wide
                        $string3_VncSharp_greyware_tool_keyword = /\\VncSharp\.exe/ nocase ascii wide
                        $string4_VncSharp_greyware_tool_keyword = /\\VncSharp\.sln/ nocase ascii wide
                        $string5_VncSharp_greyware_tool_keyword = "73e83646-1d53-4dec-950a-a48559e438e8" nocase ascii wide
                        $string6_VncSharp_greyware_tool_keyword = "dfedf8e6a6cdb480ee00545da5e7d5370b5b7057d0b274f3a6f9cf4a192a87e6" nocase ascii wide
                        $string7_VncSharp_greyware_tool_keyword = "E0695F0F-0FAF-44BC-AE55-A1FCBFE70271" nocase ascii wide
                        $string8_VncSharp_greyware_tool_keyword = "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683" nocase ascii wide
                        $string9_VncSharp_greyware_tool_keyword = "humphd/VncSharp" nocase ascii wide

    condition:
        any of them
}