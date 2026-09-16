rule daphne
{
    meta:
        description = "Detection patterns for the tool 'daphne' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "daphne"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/daphne\.git/ nocase ascii wide
                        $string2 = "/daphne-x64" nocase ascii wide
                        $string3 = "codewhitesec/daphne" nocase ascii wide
                        $string4 = /daphne\-main\.zip/ nocase ascii wide
                        $string5 = /daphne\-x64\s.{0,1000}\spid\=/ nocase ascii wide

    condition:
        any of them
}