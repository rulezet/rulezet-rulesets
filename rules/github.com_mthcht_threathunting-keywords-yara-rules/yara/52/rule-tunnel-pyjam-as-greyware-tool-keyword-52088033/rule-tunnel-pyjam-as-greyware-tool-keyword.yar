rule rule_tunnel_pyjam_as_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tunnel.pyjam.as' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnel.pyjam.as"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tunnel_pyjam_as_greyware_tool_keyword = "/bin/bash -c 'wg addconf "
                        $string2_tunnel_pyjam_as_greyware_tool_keyword = /\/etc\/wireguard\/.{0,1000}\.conf/
                        $string3_tunnel_pyjam_as_greyware_tool_keyword = "/root/tunnel"
                        $string4_tunnel_pyjam_as_greyware_tool_keyword = "9e3c014399ad61b61a1fa5fa58de95a4ddfded6ff863c413cea089f2d92f9d70"
                        $string5_tunnel_pyjam_as_greyware_tool_keyword = "Overwrite by setting TUNNEL_WG_INTERFACE_NAME"
                        $string6_tunnel_pyjam_as_greyware_tool_keyword = /pyjam\.as\/tunnel/
                        $string7_tunnel_pyjam_as_greyware_tool_keyword = /tunnel\.pyjam\.as/
                        $string8_tunnel_pyjam_as_greyware_tool_keyword = "TUNNEL_WG_INTERFACE_NAME="

    condition:
        any of them
}