rule trycloudflare_com
{
    meta:
        description = "Detection patterns for the tool 'trycloudflare.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "trycloudflare.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.trycloudfare\.com.{0,1000}DavWWWRoot/ nocase ascii wide
                        $string2 = /http\:\/\/.{0,1000}\.trycloudfare\.com/ nocase ascii wide
                        $string3 = /https\:\/\/.{0,1000}\.trycloudfare\.com/ nocase ascii wide
                        $string4 = /https\:\/\/.{0,1000}\.trycloudflare\.com/ nocase ascii wide
                        $string5 = /location\:\\\\.{0,1000}\.trycloudfare\.com/ nocase ascii wide
                        $string6 = /QNAME.{0,1000}\.trycloudfare\.com/ nocase ascii wide

    condition:
        any of them
}