rule rule_cdn_proxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cdn-proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cdn-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cdn_proxy_offensive_tool_keyword = "cdn_proxy cloudflare " nocase ascii wide
                        $string2_cdn_proxy_offensive_tool_keyword = /cdn_proxy_burp_ext\.py/ nocase ascii wide
                        $string3_cdn_proxy_offensive_tool_keyword = "cdn-proxy -" nocase ascii wide
                        $string4_cdn_proxy_offensive_tool_keyword = "cdn-proxy cloudfront " nocase ascii wide
                        $string5_cdn_proxy_offensive_tool_keyword = /cdn\-proxy\.git/ nocase ascii wide
                        $string6_cdn_proxy_offensive_tool_keyword = "cdn-proxy/burp_extension" nocase ascii wide
                        $string7_cdn_proxy_offensive_tool_keyword = "Cdn-Proxy-Host" nocase ascii wide
                        $string8_cdn_proxy_offensive_tool_keyword = "Cdn-Proxy-Origin" nocase ascii wide
                        $string9_cdn_proxy_offensive_tool_keyword = "cdn-scanner -" nocase ascii wide
                        $string10_cdn_proxy_offensive_tool_keyword = "install cdn-proxy" nocase ascii wide

    condition:
        any of them
}