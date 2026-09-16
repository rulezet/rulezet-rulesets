rule DuckDuckC2
{
    meta:
        description = "Detection patterns for the tool 'DuckDuckC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DuckDuckC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DuckDuckC2\.git/ nocase ascii wide
                        $string2 = "cd  DuckDuckC2" nocase ascii wide
                        $string3 = "DuckDuckC2-main" nocase ascii wide
                        $string4 = /https\:\/\/proxy\.duckduckgo\.com\/iu\/\?u\=https\:\/\/pdxkmdcepvahysnnxe\.pythonanywhere\.com\/image\.jpg\?cmd\=/ nocase ascii wide
                        $string5 = "nopcorn/DuckDuckC2" nocase ascii wide

    condition:
        any of them
}