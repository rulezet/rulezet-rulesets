rule rule_trycloudflare_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'trycloudflare.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "trycloudflare.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_trycloudflare_com_greyware_tool_keyword = /\.trycloudfare\.com.{0,1000}DavWWWRoot/ nocase ascii wide
                        $string2_trycloudflare_com_greyware_tool_keyword = /http\:\/\/.{0,1000}\.trycloudfare\.com/ nocase ascii wide
                        $string3_trycloudflare_com_greyware_tool_keyword = /https\:\/\/.{0,1000}\.trycloudfare\.com/ nocase ascii wide
                        $string4_trycloudflare_com_greyware_tool_keyword = /https\:\/\/.{0,1000}\.trycloudflare\.com/ nocase ascii wide
                        $string5_trycloudflare_com_greyware_tool_keyword = /location\:\\\\.{0,1000}\.trycloudfare\.com/ nocase ascii wide
                        $string6_trycloudflare_com_greyware_tool_keyword = /QNAME.{0,1000}\.trycloudfare\.com/ nocase ascii wide

    condition:
        any of them
}