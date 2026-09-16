rule rule_SessionSearcher_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SessionSearcher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionSearcher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SessionSearcher_offensive_tool_keyword = /\/SessionSearcher\.exe/ nocase ascii wide
                        $string2_SessionSearcher_offensive_tool_keyword = /\\SessionSearcher\.csproj/ nocase ascii wide
                        $string3_SessionSearcher_offensive_tool_keyword = /\\SessionSearcher\.exe/ nocase ascii wide

    condition:
        any of them
}