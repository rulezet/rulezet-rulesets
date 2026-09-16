rule HTMLSmuggler
{
    meta:
        description = "Detection patterns for the tool 'HTMLSmuggler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HTMLSmuggler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HTMLSmuggler\.git/ nocase ascii wide
                        $string2 = "/HTMLSmuggler/" nocase ascii wide
                        $string3 = /\\HTMLSmuggler\\/ nocase ascii wide
                        $string4 = "D00Movenok/HTMLSmuggler" nocase ascii wide
                        $string5 = "HTMLSmuggler-main" nocase ascii wide

    condition:
        any of them
}