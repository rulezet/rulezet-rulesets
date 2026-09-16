rule rule_hypertunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hypertunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hypertunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_hypertunnel_greyware_tool_keyword = /\/hypertunnel\.git/ nocase ascii wide
                        $string2_hypertunnel_greyware_tool_keyword = /\/hypertunnel\-tcp\-relay.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string3_hypertunnel_greyware_tool_keyword = /\/hypertunnel\-tcp\-relay.{0,1000}\.zip/ nocase ascii wide
                        $string4_hypertunnel_greyware_tool_keyword = "23fe91b0f562494d22d23a02a05f35847520170930ceb92cffa6783229b46d78" nocase ascii wide
                        $string5_hypertunnel_greyware_tool_keyword = "berstend/hypertunnel" nocase ascii wide
                        $string6_hypertunnel_greyware_tool_keyword = /https\:\/\/hypertunnel\.ga/ nocase ascii wide
                        $string7_hypertunnel_greyware_tool_keyword = /hypertunnel\.lvh\.me/ nocase ascii wide
                        $string8_hypertunnel_greyware_tool_keyword = "hypertunnel-server@latest" nocase ascii wide
                        $string9_hypertunnel_greyware_tool_keyword = /local\.hypertunnel\.lvh\.me/ nocase ascii wide
                        $string10_hypertunnel_greyware_tool_keyword = /MIIJKgIBAAKCAgEAuvAs1YNtpCaqyG3Rkyutst3uIjzYLQTPWf1v\+OLi3GgzshUB/ nocase ascii wide
                        $string11_hypertunnel_greyware_tool_keyword = "npm install hypertunnel-server" nocase ascii wide
                        $string12_hypertunnel_greyware_tool_keyword = "packages/hypertunnel/" nocase ascii wide
                        $string13_hypertunnel_greyware_tool_keyword = "packages/hypertunnel-server" nocase ascii wide
                        $string14_hypertunnel_greyware_tool_keyword = "packages/hypertunnel-tcp-relay" nocase ascii wide

    condition:
        any of them
}