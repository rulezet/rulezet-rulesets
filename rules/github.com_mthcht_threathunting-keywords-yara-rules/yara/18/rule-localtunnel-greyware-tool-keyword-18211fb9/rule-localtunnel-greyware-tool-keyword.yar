rule rule_localtunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'localtunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_localtunnel_greyware_tool_keyword = " --name localtunnel " nocase ascii wide
                        $string2_localtunnel_greyware_tool_keyword = /\.localltunnel\.me/ nocase ascii wide
                        $string3_localtunnel_greyware_tool_keyword = /\/go\-localtunnel\.git/ nocase ascii wide
                        $string4_localtunnel_greyware_tool_keyword = /\/gotunnelme\.git/ nocase ascii wide
                        $string5_localtunnel_greyware_tool_keyword = /\/localtunnel\.git/ nocase ascii wide
                        $string6_localtunnel_greyware_tool_keyword = /\/localtunnel\.js/ nocase ascii wide
                        $string7_localtunnel_greyware_tool_keyword = "d0274f036468ef236d3a526bb6235289bdbe4c8828ee7feee1829a026f5f3bec" nocase ascii wide
                        $string8_localtunnel_greyware_tool_keyword = "e367bbc84b75901ae680472b7b848ee4f10fbc356e7dd8de5c2c46000cf78818" nocase ascii wide
                        $string9_localtunnel_greyware_tool_keyword = "gotunnelme " nocase ascii wide
                        $string10_localtunnel_greyware_tool_keyword = /https\:\/\/localtunnel\.me/ nocase ascii wide
                        $string11_localtunnel_greyware_tool_keyword = "install -g localtunnel" nocase ascii wide
                        $string12_localtunnel_greyware_tool_keyword = "localtunnel/go-localtunnel" nocase ascii wide
                        $string13_localtunnel_greyware_tool_keyword = /localtunnel\/server\.git/ nocase ascii wide
                        $string14_localtunnel_greyware_tool_keyword = "localtunnel-server:latest" nocase ascii wide
                        $string15_localtunnel_greyware_tool_keyword = "NoahShen/gotunnelme" nocase ascii wide
                        $string16_localtunnel_greyware_tool_keyword = "npx localtunnel " nocase ascii wide
                        $string17_localtunnel_greyware_tool_keyword = "src/gotunnelme/" nocase ascii wide
                        $string18_localtunnel_greyware_tool_keyword = "yarn add localtunnel" nocase ascii wide

    condition:
        any of them
}