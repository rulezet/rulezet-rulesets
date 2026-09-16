rule rule_KrakenMask_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KrakenMask' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrakenMask"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KrakenMask_offensive_tool_keyword = /\/KrakenMask\.git/ nocase ascii wide
                        $string2_KrakenMask_offensive_tool_keyword = "C7E4B529-6372-449A-9184-74E74E432FE8" nocase ascii wide
                        $string3_KrakenMask_offensive_tool_keyword = "Kraken Mask by @DallasFR" nocase ascii wide
                        $string4_KrakenMask_offensive_tool_keyword = "KrakenMask-main" nocase ascii wide
                        $string5_KrakenMask_offensive_tool_keyword = "RtlDallas/KrakenMask" nocase ascii wide

    condition:
        any of them
}