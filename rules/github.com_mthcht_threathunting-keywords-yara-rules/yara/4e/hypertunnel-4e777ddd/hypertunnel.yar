rule hypertunnel
{
    meta:
        description = "Detection patterns for the tool 'hypertunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hypertunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/hypertunnel\.git/ nocase ascii wide
                        $string2 = /\/hypertunnel\-tcp\-relay.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string3 = /\/hypertunnel\-tcp\-relay.{0,1000}\.zip/ nocase ascii wide
                        $string4 = "23fe91b0f562494d22d23a02a05f35847520170930ceb92cffa6783229b46d78" nocase ascii wide
                        $string5 = "berstend/hypertunnel" nocase ascii wide
                        $string6 = /https\:\/\/hypertunnel\.ga/ nocase ascii wide
                        $string7 = /hypertunnel\.lvh\.me/ nocase ascii wide
                        $string8 = "hypertunnel-server@latest" nocase ascii wide
                        $string9 = /local\.hypertunnel\.lvh\.me/ nocase ascii wide
                        $string10 = /MIIJKgIBAAKCAgEAuvAs1YNtpCaqyG3Rkyutst3uIjzYLQTPWf1v\+OLi3GgzshUB/ nocase ascii wide
                        $string11 = "npm install hypertunnel-server" nocase ascii wide
                        $string12 = "packages/hypertunnel/" nocase ascii wide
                        $string13 = "packages/hypertunnel-server" nocase ascii wide
                        $string14 = "packages/hypertunnel-tcp-relay" nocase ascii wide

    condition:
        any of them
}