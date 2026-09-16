rule rule_DuckDuckC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DuckDuckC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DuckDuckC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DuckDuckC2_offensive_tool_keyword = /\/DuckDuckC2\.git/ nocase ascii wide
                        $string2_DuckDuckC2_offensive_tool_keyword = "cd  DuckDuckC2" nocase ascii wide
                        $string3_DuckDuckC2_offensive_tool_keyword = "DuckDuckC2-main" nocase ascii wide
                        $string4_DuckDuckC2_offensive_tool_keyword = /https\:\/\/proxy\.duckduckgo\.com\/iu\/\?u\=https\:\/\/pdxkmdcepvahysnnxe\.pythonanywhere\.com\/image\.jpg\?cmd\=/ nocase ascii wide
                        $string5_DuckDuckC2_offensive_tool_keyword = "nopcorn/DuckDuckC2" nocase ascii wide

    condition:
        any of them
}