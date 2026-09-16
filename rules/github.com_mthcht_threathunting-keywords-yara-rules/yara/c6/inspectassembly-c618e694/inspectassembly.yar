rule InspectAssembly
{
    meta:
        description = "Detection patterns for the tool 'InspectAssembly' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InspectAssembly"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /InspectAssembly\.csproj/ nocase ascii wide
                        $string2 = /InspectAssembly\.exe/ nocase ascii wide

    condition:
        any of them
}