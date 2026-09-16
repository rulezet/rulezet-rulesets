rule rule_PhantomService_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PhantomService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhantomService"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PhantomService_offensive_tool_keyword = "/master/PhantomService/" nocase ascii wide
                        $string2_PhantomService_offensive_tool_keyword = /\]\sFound\snon\-ASCII\sservice\:\s/ nocase ascii wide
                        $string3_PhantomService_offensive_tool_keyword = /PhantomService\.csproj/ nocase ascii wide
                        $string4_PhantomService_offensive_tool_keyword = /PhantomService\.exe/ nocase ascii wide

    condition:
        any of them
}