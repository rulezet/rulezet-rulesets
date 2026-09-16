rule rule_updog_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'updog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "updog"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_updog_greyware_tool_keyword = /\/updog\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string2_updog_greyware_tool_keyword = /\/updog\.git/ nocase ascii wide
                        $string3_updog_greyware_tool_keyword = "/updog/archive/updog-" nocase ascii wide
                        $string4_updog_greyware_tool_keyword = /\\updog\-master\\/ nocase ascii wide
                        $string5_updog_greyware_tool_keyword = /pip.{0,1000}\sinstall\supdog/ nocase ascii wide
                        $string6_updog_greyware_tool_keyword = "sc0tfree/updog" nocase ascii wide
                        $string7_updog_greyware_tool_keyword = "updog --" nocase ascii wide
                        $string8_updog_greyware_tool_keyword = "updog -d /" nocase ascii wide
                        $string9_updog_greyware_tool_keyword = "updog -p " nocase ascii wide
                        $string10_updog_greyware_tool_keyword = /updog\-master\.zip/ nocase ascii wide

    condition:
        any of them
}