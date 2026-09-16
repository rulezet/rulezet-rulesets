rule wetransfer
{
    meta:
        description = "Detection patterns for the tool 'wetransfer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wetransfer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/we\.tl\/t\-/ nocase ascii wide
                        $string2 = /https\:\/\/wetransfer\.com\/api\/v4\/transfers\// nocase ascii wide
                        $string3 = /https\:\/\/wetransfer\.com\/downloads\// nocase ascii wide

    condition:
        any of them
}