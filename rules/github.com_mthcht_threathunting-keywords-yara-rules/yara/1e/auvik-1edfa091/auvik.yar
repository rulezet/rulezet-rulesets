rule auvik
{
    meta:
        description = "Detection patterns for the tool 'auvik' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "auvik"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\>Auvik\sNetworks\sInc\.\</ nocase ascii wide
                        $string2 = /auvik\.agent\.exe/ nocase ascii wide
                        $string3 = /AuvikService\.exe/ nocase ascii wide
                        $string4 = /https\:\/\/.{0,1000}\.my\.auvik\.com\// nocase ascii wide

    condition:
        any of them
}