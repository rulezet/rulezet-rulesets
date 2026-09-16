rule rule_SwampThing_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SwampThing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SwampThing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SwampThing_offensive_tool_keyword = " -FakeCmdLine " nocase ascii wide
                        $string2_SwampThing_offensive_tool_keyword = " -RealCmdLine " nocase ascii wide
                        $string3_SwampThing_offensive_tool_keyword = /\\SpoofCmdLine\\TheThing/ nocase ascii wide
                        $string4_SwampThing_offensive_tool_keyword = /\\SwampThing\.csproj/ nocase ascii wide
                        $string5_SwampThing_offensive_tool_keyword = /\\TheThing\.exe/ nocase ascii wide
                        $string6_SwampThing_offensive_tool_keyword = "master/SwampThing" nocase ascii wide
                        $string7_SwampThing_offensive_tool_keyword = /SwampThing\.exe/ nocase ascii wide
                        $string8_SwampThing_offensive_tool_keyword = /SwampThing\.pdb/ nocase ascii wide
                        $string9_SwampThing_offensive_tool_keyword = /SwampThing\.sln/ nocase ascii wide

    condition:
        any of them
}