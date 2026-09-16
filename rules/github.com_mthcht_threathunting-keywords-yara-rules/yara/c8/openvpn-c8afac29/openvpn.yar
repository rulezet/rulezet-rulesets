rule OPENVPN
{
    meta:
        description = "Detection patterns for the tool 'OPENVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OPENVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "\"-----BEGIN OpenVPN Static key" nocase ascii wide
                        $string2 = /\/openvpn\.exe/ nocase ascii wide
                        $string3 = /\\bin\\tapinstall\.exe/ nocase ascii wide
                        $string4 = /\\Licenses\\OpenVPN\.txt/ nocase ascii wide
                        $string5 = /\\openvpn\.exe/ nocase ascii wide
                        $string6 = /\\Program\sFiles\\TAP\-Windows\\/ nocase ascii wide
                        $string7 = /\\Root\\InventoryApplicationFile\\tap\-windows/ nocase ascii wide
                        $string8 = /\\SOFTWARE\\TAP\-Windows/ nocase ascii wide
                        $string9 = /\\tap\-windows\-.{0,1000}\.exe/ nocase ascii wide
                        $string10 = ">the openvpn project<" nocase ascii wide

    condition:
        any of them
}