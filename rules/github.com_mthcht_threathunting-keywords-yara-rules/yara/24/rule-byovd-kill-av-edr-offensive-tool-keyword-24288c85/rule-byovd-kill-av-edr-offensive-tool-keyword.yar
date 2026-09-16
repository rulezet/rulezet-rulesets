rule rule_BYOVD_kill_av_edr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BYOVD_kill_av_edr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BYOVD_kill_av_edr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BYOVD_kill_av_edr_offensive_tool_keyword = /\\\\\\\\\.\\\\aswSP_Avar/ nocase ascii wide
                        $string2_BYOVD_kill_av_edr_offensive_tool_keyword = /BYOVD_kill_av_edr\./ nocase ascii wide

    condition:
        any of them
}