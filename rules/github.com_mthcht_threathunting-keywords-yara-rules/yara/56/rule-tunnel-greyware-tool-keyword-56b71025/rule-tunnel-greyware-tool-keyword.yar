rule rule_tunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tunnel_greyware_tool_keyword = /\sthe\sservers\sWireguard\sinterface\./ nocase ascii wide
                        $string2_tunnel_greyware_tool_keyword = /\.tunnel\.pyjam\.as/ nocase ascii wide
                        $string3_tunnel_greyware_tool_keyword = "// Package tunnel is a server/client package that enables to proxy public"
                        $string4_tunnel_greyware_tool_keyword = /\/etc\/wireguard\/.{0,1000}\.conf/
                        $string5_tunnel_greyware_tool_keyword = /\/etc\/wireguard\/.{0,1000}\.conf/
                        $string6_tunnel_greyware_tool_keyword = /\/pyjam\.as\/tunnel/ nocase ascii wide
                        $string7_tunnel_greyware_tool_keyword = /\/tunnel\/server\.go/
                        $string8_tunnel_greyware_tool_keyword = /\/tunnel\/tunnel\.py/
                        $string9_tunnel_greyware_tool_keyword = /\/tunnel\/tunnel\.service/
                        $string10_tunnel_greyware_tool_keyword = /\/tunnel\-main\.tar\.gz/
                        $string11_tunnel_greyware_tool_keyword = "3579ab708388d7be3e66c1a45deea0f6a249865ce4105310d8fe340ed28accca" nocase ascii wide
                        $string12_tunnel_greyware_tool_keyword = "447a5e8b424ebc3b82e909ab8c585fda579881ad26c35cba3c32b77896008c62" nocase ascii wide
                        $string13_tunnel_greyware_tool_keyword = "9e3c014399ad61b61a1fa5fa58de95a4ddfded6ff863c413cea089f2d92f9d70" nocase ascii wide
                        $string14_tunnel_greyware_tool_keyword = "c9165f1628aa7d5a75b907d71efda4fa4ab1fa8bb2ee12ef86478ef6e2c3e162" nocase ascii wide
                        $string15_tunnel_greyware_tool_keyword = "e82ae72bb202db9bae86dc81cf4df152b6d8d3b5062295004b8ae92088904dc7" nocase ascii wide
                        $string16_tunnel_greyware_tool_keyword = /github.{0,1000}koding\/tunnel/ nocase ascii wide
                        $string17_tunnel_greyware_tool_keyword = /http\:\/\/arslan\.koding\.io\// nocase ascii wide
                        $string18_tunnel_greyware_tool_keyword = /https\:\/\/tunnel\.pyjam\.as\// nocase ascii wide
                        $string19_tunnel_greyware_tool_keyword = /https\:\/\/www\.wireguard\.com\/install/ nocase ascii wide
                        $string20_tunnel_greyware_tool_keyword = /tunnel\/httpproxy\.go/ nocase ascii wide
                        $string21_tunnel_greyware_tool_keyword = /wg\-quick\sdown\s\.\/tunnel\.conf/
                        $string22_tunnel_greyware_tool_keyword = /wg\-quick\sup\s\.\/tunnel\.conf/
                        $string23_tunnel_greyware_tool_keyword = /Write\sWireguard\sserver\sconfiguration\sto\sdisk\./ nocase ascii wide
                        $string24_tunnel_greyware_tool_keyword = /Write\sWireguard\sserver\sconfiguration\sto\sdisk\./ nocase ascii wide

    condition:
        any of them
}