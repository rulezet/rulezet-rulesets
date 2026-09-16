rule PhantomService
{
    meta:
        description = "Detection patterns for the tool 'PhantomService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhantomService"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/master/PhantomService/" nocase ascii wide
                        $string2 = /\]\sFound\snon\-ASCII\sservice\:\s/ nocase ascii wide
                        $string3 = /PhantomService\.csproj/ nocase ascii wide
                        $string4 = /PhantomService\.exe/ nocase ascii wide

    condition:
        any of them
}