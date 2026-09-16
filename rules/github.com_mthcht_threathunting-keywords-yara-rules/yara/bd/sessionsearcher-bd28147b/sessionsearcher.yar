rule SessionSearcher
{
    meta:
        description = "Detection patterns for the tool 'SessionSearcher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionSearcher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SessionSearcher\.exe/ nocase ascii wide
                        $string2 = /\\SessionSearcher\.csproj/ nocase ascii wide
                        $string3 = /\\SessionSearcher\.exe/ nocase ascii wide

    condition:
        any of them
}