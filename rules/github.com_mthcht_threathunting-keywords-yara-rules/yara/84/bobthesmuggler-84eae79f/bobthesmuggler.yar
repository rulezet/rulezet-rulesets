rule BobTheSmuggler
{
    meta:
        description = "Detection patterns for the tool 'BobTheSmuggler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BobTheSmuggler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSharpHound\.html/ nocase ascii wide
                        $string2 = /\/BobTheSmuggler\.git/ nocase ascii wide
                        $string3 = /\\SharpHound\.html/ nocase ascii wide
                        $string4 = /BobTheSmuggler\.py/ nocase ascii wide
                        $string5 = "BobTheSmuggler-main" nocase ascii wide
                        $string6 = "Getting the Obfuscated JS Code" nocase ascii wide
                        $string7 = "Successfully embedded EXE into GIF" nocase ascii wide
                        $string8 = "Successfully embedded EXE into PNG" nocase ascii wide
                        $string9 = "TheCyb3rAlpha/BobTheSmuggler" nocase ascii wide
                        $string10 = "URL must be provided for GIF embedding!" nocase ascii wide
                        $string11 = "URL must be provided for PNG embedding!" nocase ascii wide

    condition:
        any of them
}