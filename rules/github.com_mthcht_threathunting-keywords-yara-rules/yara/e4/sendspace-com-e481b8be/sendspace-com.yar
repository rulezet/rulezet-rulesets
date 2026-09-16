rule sendspace_com
{
    meta:
        description = "Detection patterns for the tool 'sendspace.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sendspace.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/.{0,1000}\.sendspace\.com\/upload/ nocase ascii wide
                        $string2 = /https\:\/\/www\.sendspace\.com\/delete/ nocase ascii wide
                        $string3 = /https\:\/\/www\.sendspace\.com\/file\// nocase ascii wide

    condition:
        any of them
}