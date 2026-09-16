rule GrabChrome
{
    meta:
        description = "Detection patterns for the tool 'GrabChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GrabChrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/grabchrome\.exe/ nocase ascii wide
                        $string2 = /\\grabchrome\.exe/ nocase ascii wide
                        $string3 = /\\grbachrome\.exe/ nocase ascii wide
                        $string4 = ">grabff<" nocase ascii wide
                        $string5 = "374a98a083fc04f30b86718a9fe7a5a61d1afc22b93222a89d2b752b5da1df7e" nocase ascii wide

    condition:
        any of them
}