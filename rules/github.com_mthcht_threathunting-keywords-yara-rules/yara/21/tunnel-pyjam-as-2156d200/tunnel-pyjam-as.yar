rule tunnel_pyjam_as
{
    meta:
        description = "Detection patterns for the tool 'tunnel.pyjam.as' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnel.pyjam.as"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "/bin/bash -c 'wg addconf "
                        $string2 = /\/etc\/wireguard\/.{0,1000}\.conf/
                        $string3 = "/root/tunnel"
                        $string4 = "9e3c014399ad61b61a1fa5fa58de95a4ddfded6ff863c413cea089f2d92f9d70"
                        $string5 = "Overwrite by setting TUNNEL_WG_INTERFACE_NAME"
                        $string6 = /pyjam\.as\/tunnel/
                        $string7 = /tunnel\.pyjam\.as/
                        $string8 = "TUNNEL_WG_INTERFACE_NAME="

    condition:
        any of them
}