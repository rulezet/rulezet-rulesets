rule PassDetective
{
    meta:
        description = "Detection patterns for the tool 'PassDetective' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassDetective"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " extract --secrets --zsh" nocase ascii wide
                        $string2 = /\.\/Passdetective/
                        $string3 = /\/PassDetective\.git/ nocase ascii wide
                        $string4 = "aydinnyunus/PassDetective" nocase ascii wide
                        $string5 = "PassDetective extract" nocase ascii wide
                        $string6 = /PassDetective\-main\./ nocase ascii wide

    condition:
        any of them
}