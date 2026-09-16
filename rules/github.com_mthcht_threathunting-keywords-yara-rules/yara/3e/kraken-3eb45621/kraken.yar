rule Kraken
{
    meta:
        description = "Detection patterns for the tool 'Kraken' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kraken"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.py\s\-c\s\-m\sc2\s\-p\sutils/ nocase ascii wide
                        $string2 = "conda activate kraken" nocase ascii wide
                        $string3 = "conda create -n kraken python=" nocase ascii wide
                        $string4 = /from\slib\.config\simport\s.{0,1000}C2_COMMANDS/ nocase ascii wide
                        $string5 = /Kraken\-1\.2\.0\.zip/ nocase ascii wide
                        $string6 = "kraken-ng/Kraken" nocase ascii wide
                        $string7 = /python\skraken\.py\s\-/ nocase ascii wide

    condition:
        any of them
}