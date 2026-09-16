rule KrakenMask
{
    meta:
        description = "Detection patterns for the tool 'KrakenMask' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrakenMask"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/KrakenMask\.git/ nocase ascii wide
                        $string2 = "C7E4B529-6372-449A-9184-74E74E432FE8" nocase ascii wide
                        $string3 = "Kraken Mask by @DallasFR" nocase ascii wide
                        $string4 = "KrakenMask-main" nocase ascii wide
                        $string5 = "RtlDallas/KrakenMask" nocase ascii wide

    condition:
        any of them
}