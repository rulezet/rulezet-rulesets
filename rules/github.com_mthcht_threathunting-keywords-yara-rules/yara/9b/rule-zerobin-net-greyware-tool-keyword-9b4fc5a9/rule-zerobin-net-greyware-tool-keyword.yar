rule rule_zerobin_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'zerobin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zerobin.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_zerobin_net_greyware_tool_keyword = /http\:\/\/zerobinftagjpeeebbvyzjcqyjpmjvynj5qlexwyxe7l3vqejxnqv5qd\.onion/ nocase ascii wide
                        $string2_zerobin_net_greyware_tool_keyword = /https\:\/\/zerobin\.net\/\?/ nocase ascii wide
                        $string3_zerobin_net_greyware_tool_keyword = /https\:\/\/zerobin\.net\/js\/privatebin\.js/ nocase ascii wide

    condition:
        any of them
}