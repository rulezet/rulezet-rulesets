rule Hunter_io
{
    meta:
        description = "Detection patterns for the tool 'Hunter.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hunter.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /curl\shttps\:\/\/api\.hunter\.io\/v2\/domain\-search\?domain\=/ nocase ascii wide
                        $string2 = /curl\shttps\:\/\/api\.hunter\.io\/v2\/email\-finder\?domain\=/ nocase ascii wide
                        $string3 = /curl\shttps\:\/\/api\.hunter\.io\/v2\/email\-verifier\?email\=/ nocase ascii wide
                        $string4 = /https\:\/\/api\.hunter\.io\// nocase ascii wide
                        $string5 = /https\:\/\/hunter\.io\// nocase ascii wide

    condition:
        any of them
}