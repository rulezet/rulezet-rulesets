rule rule_fetch_some_proxies_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fetch-some-proxies' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fetch-some-proxies"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fetch_some_proxies_offensive_tool_keyword = /\\"https\:\/\/api\.ipify\.org\/\?format\=text\\"\,\s\\"https\:\/\/myexternalip\.com\/raw\\"\,\s\\"https\:\/\/wtfismyip\.com\/text\\"\,\s\\"https\:\/\/icanhazip\.com\/\\"\,\s\\"https\:\/\/ip4\.seeip\.org\\"/ nocase ascii wide
                        $string2_fetch_some_proxies_offensive_tool_keyword = /\/fetch\-some\-proxies\.git/ nocase ascii wide
                        $string3_fetch_some_proxies_offensive_tool_keyword = /\|f\|\|e\|\|t\|\|c\|\|h\|\|\-\|\|s\|\|o\|\|m\|\|e\|\|\-\|\|p\|\|r\|\|o\|\|x\|\|i\|\|e\|\|s\|/ nocase ascii wide
                        $string4_fetch_some_proxies_offensive_tool_keyword = "daff98d2dd945ec0f5d8ef476de48e57074416a50389639d01aa54444d2cfb44" nocase ascii wide
                        $string5_fetch_some_proxies_offensive_tool_keyword = /https\:\/\/raw\.githubusercontent\.com\/stamparm\/aux\/master\/fetch\-some\-list\.txt/ nocase ascii wide
                        $string6_fetch_some_proxies_offensive_tool_keyword = "python -c \"import fetch\"" nocase ascii wide
                        $string7_fetch_some_proxies_offensive_tool_keyword = "stamparm/fetch-some-proxies" nocase ascii wide

    condition:
        any of them
}