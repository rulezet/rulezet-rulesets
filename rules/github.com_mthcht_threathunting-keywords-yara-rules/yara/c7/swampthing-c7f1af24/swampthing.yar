rule SwampThing
{
    meta:
        description = "Detection patterns for the tool 'SwampThing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SwampThing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -FakeCmdLine " nocase ascii wide
                        $string2 = " -RealCmdLine " nocase ascii wide
                        $string3 = /\\SpoofCmdLine\\TheThing/ nocase ascii wide
                        $string4 = /\\SwampThing\.csproj/ nocase ascii wide
                        $string5 = /\\TheThing\.exe/ nocase ascii wide
                        $string6 = "master/SwampThing" nocase ascii wide
                        $string7 = /SwampThing\.exe/ nocase ascii wide
                        $string8 = /SwampThing\.pdb/ nocase ascii wide
                        $string9 = /SwampThing\.sln/ nocase ascii wide

    condition:
        any of them
}