rule rule_OPENVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OPENVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OPENVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_OPENVPN_greyware_tool_keyword = "\"-----BEGIN OpenVPN Static key" nocase ascii wide
                        $string2_OPENVPN_greyware_tool_keyword = /\/openvpn\.exe/ nocase ascii wide
                        $string3_OPENVPN_greyware_tool_keyword = /\\bin\\tapinstall\.exe/ nocase ascii wide
                        $string4_OPENVPN_greyware_tool_keyword = /\\Licenses\\OpenVPN\.txt/ nocase ascii wide
                        $string5_OPENVPN_greyware_tool_keyword = /\\openvpn\.exe/ nocase ascii wide
                        $string6_OPENVPN_greyware_tool_keyword = /\\Program\sFiles\\TAP\-Windows\\/ nocase ascii wide
                        $string7_OPENVPN_greyware_tool_keyword = /\\Root\\InventoryApplicationFile\\tap\-windows/ nocase ascii wide
                        $string8_OPENVPN_greyware_tool_keyword = /\\SOFTWARE\\TAP\-Windows/ nocase ascii wide
                        $string9_OPENVPN_greyware_tool_keyword = /\\tap\-windows\-.{0,1000}\.exe/ nocase ascii wide
                        $string10_OPENVPN_greyware_tool_keyword = ">the openvpn project<" nocase ascii wide

    condition:
        any of them
}