rule rule_BobTheSmuggler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BobTheSmuggler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BobTheSmuggler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BobTheSmuggler_offensive_tool_keyword = /\sSharpHound\.html/ nocase ascii wide
                        $string2_BobTheSmuggler_offensive_tool_keyword = /\/BobTheSmuggler\.git/ nocase ascii wide
                        $string3_BobTheSmuggler_offensive_tool_keyword = /\\SharpHound\.html/ nocase ascii wide
                        $string4_BobTheSmuggler_offensive_tool_keyword = /BobTheSmuggler\.py/ nocase ascii wide
                        $string5_BobTheSmuggler_offensive_tool_keyword = "BobTheSmuggler-main" nocase ascii wide
                        $string6_BobTheSmuggler_offensive_tool_keyword = "Getting the Obfuscated JS Code" nocase ascii wide
                        $string7_BobTheSmuggler_offensive_tool_keyword = "Successfully embedded EXE into GIF" nocase ascii wide
                        $string8_BobTheSmuggler_offensive_tool_keyword = "Successfully embedded EXE into PNG" nocase ascii wide
                        $string9_BobTheSmuggler_offensive_tool_keyword = "TheCyb3rAlpha/BobTheSmuggler" nocase ascii wide
                        $string10_BobTheSmuggler_offensive_tool_keyword = "URL must be provided for GIF embedding!" nocase ascii wide
                        $string11_BobTheSmuggler_offensive_tool_keyword = "URL must be provided for PNG embedding!" nocase ascii wide

    condition:
        any of them
}