rule o365spray
{
    meta:
        description = "Detection patterns for the tool 'o365spray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365spray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\so365spray\.py/ nocase ascii wide
                        $string2 = /\/o365spray\.git/ nocase ascii wide
                        $string3 = /\/o365spray\.py/ nocase ascii wide
                        $string4 = /\\o365spray\.py/ nocase ascii wide
                        $string5 = "0xZDH/o365spray" nocase ascii wide
                        $string6 = "d4ba2464d2d3450db40ac57c7e0d6d7a7e4ac72c44cbd6ce9e4b3366f3a8907b" nocase ascii wide
                        $string7 = /from\so365spray\.__main__/ nocase ascii wide
                        $string8 = /from\so365spray\.core\.utils/ nocase ascii wide
                        $string9 = "Invoke-AzureAdPasswordSprayAttack" nocase ascii wide
                        $string10 = "o365spray --enum " nocase ascii wide
                        $string11 = "o365spray --spray " nocase ascii wide
                        $string12 = "o365spray --validate" nocase ascii wide
                        $string13 = /o365spray\.core\.handlers\.sprayer/ nocase ascii wide
                        $string14 = "Password spraying using paired usernames:passwords" nocase ascii wide
                        $string15 = "Running password spray against %d users" nocase ascii wide

    condition:
        any of them
}