rule cdn_proxy
{
    meta:
        description = "Detection patterns for the tool 'cdn-proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cdn-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "cdn_proxy cloudflare " nocase ascii wide
                        $string2 = /cdn_proxy_burp_ext\.py/ nocase ascii wide
                        $string3 = "cdn-proxy -" nocase ascii wide
                        $string4 = "cdn-proxy cloudfront " nocase ascii wide
                        $string5 = /cdn\-proxy\.git/ nocase ascii wide
                        $string6 = "cdn-proxy/burp_extension" nocase ascii wide
                        $string7 = "Cdn-Proxy-Host" nocase ascii wide
                        $string8 = "Cdn-Proxy-Origin" nocase ascii wide
                        $string9 = "cdn-scanner -" nocase ascii wide
                        $string10 = "install cdn-proxy" nocase ascii wide

    condition:
        any of them
}