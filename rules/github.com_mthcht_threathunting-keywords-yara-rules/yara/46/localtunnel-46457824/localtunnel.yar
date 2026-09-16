rule localtunnel
{
    meta:
        description = "Detection patterns for the tool 'localtunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " --name localtunnel " nocase ascii wide
                        $string2 = /\.localltunnel\.me/ nocase ascii wide
                        $string3 = /\/go\-localtunnel\.git/ nocase ascii wide
                        $string4 = /\/gotunnelme\.git/ nocase ascii wide
                        $string5 = /\/localtunnel\.git/ nocase ascii wide
                        $string6 = /\/localtunnel\.js/ nocase ascii wide
                        $string7 = "d0274f036468ef236d3a526bb6235289bdbe4c8828ee7feee1829a026f5f3bec" nocase ascii wide
                        $string8 = "e367bbc84b75901ae680472b7b848ee4f10fbc356e7dd8de5c2c46000cf78818" nocase ascii wide
                        $string9 = "gotunnelme " nocase ascii wide
                        $string10 = /https\:\/\/localtunnel\.me/ nocase ascii wide
                        $string11 = "install -g localtunnel" nocase ascii wide
                        $string12 = "localtunnel/go-localtunnel" nocase ascii wide
                        $string13 = /localtunnel\/server\.git/ nocase ascii wide
                        $string14 = "localtunnel-server:latest" nocase ascii wide
                        $string15 = "NoahShen/gotunnelme" nocase ascii wide
                        $string16 = "npx localtunnel " nocase ascii wide
                        $string17 = "src/gotunnelme/" nocase ascii wide
                        $string18 = "yarn add localtunnel" nocase ascii wide

    condition:
        any of them
}