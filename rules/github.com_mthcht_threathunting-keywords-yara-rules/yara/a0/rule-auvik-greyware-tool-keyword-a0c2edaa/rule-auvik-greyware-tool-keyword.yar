rule rule_auvik_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'auvik' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "auvik"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_auvik_greyware_tool_keyword = /\>Auvik\sNetworks\sInc\.\</ nocase ascii wide
                        $string2_auvik_greyware_tool_keyword = /auvik\.agent\.exe/ nocase ascii wide
                        $string3_auvik_greyware_tool_keyword = /AuvikService\.exe/ nocase ascii wide
                        $string4_auvik_greyware_tool_keyword = /https\:\/\/.{0,1000}\.my\.auvik\.com\// nocase ascii wide

    condition:
        any of them
}