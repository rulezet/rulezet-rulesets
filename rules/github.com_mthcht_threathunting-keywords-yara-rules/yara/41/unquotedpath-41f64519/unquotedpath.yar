rule UnquotedPath
{
    meta:
        description = "Detection patterns for the tool 'UnquotedPath' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnquotedPath"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "master/UnquotedPath" nocase ascii wide
                        $string2 = /UnquotedPath\.csproj/ nocase ascii wide
                        $string3 = /UnquotedPath\.exe/ nocase ascii wide

    condition:
        any of them
}