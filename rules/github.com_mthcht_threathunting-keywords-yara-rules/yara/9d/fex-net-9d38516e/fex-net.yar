rule fex_net
{
    meta:
        description = "Detection patterns for the tool 'fex.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fex.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/.{0,1000}\.fex\.net\/download\// nocase ascii wide
                        $string2 = /https\:\/\/.{0,1000}\.fex\.net\/upload\// nocase ascii wide
                        $string3 = /https\:\/\/api\.fex\.net\/api\/v1\/anonymous\/file/ nocase ascii wide

    condition:
        any of them
}