rule rule_Kraken_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Kraken' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kraken"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Kraken_offensive_tool_keyword = /\.py\s\-c\s\-m\sc2\s\-p\sutils/ nocase ascii wide
                        $string2_Kraken_offensive_tool_keyword = "conda activate kraken" nocase ascii wide
                        $string3_Kraken_offensive_tool_keyword = "conda create -n kraken python=" nocase ascii wide
                        $string4_Kraken_offensive_tool_keyword = /from\slib\.config\simport\s.{0,1000}C2_COMMANDS/ nocase ascii wide
                        $string5_Kraken_offensive_tool_keyword = /Kraken\-1\.2\.0\.zip/ nocase ascii wide
                        $string6_Kraken_offensive_tool_keyword = "kraken-ng/Kraken" nocase ascii wide
                        $string7_Kraken_offensive_tool_keyword = /python\skraken\.py\s\-/ nocase ascii wide

    condition:
        any of them
}