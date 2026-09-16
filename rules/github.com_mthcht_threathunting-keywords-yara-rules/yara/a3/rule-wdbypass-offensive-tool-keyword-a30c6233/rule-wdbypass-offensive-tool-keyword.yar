rule rule_WDBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WDBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WDBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WDBypass_offensive_tool_keyword = "\"Starting Elevating to SYSTEM\"" nocase ascii wide
                        $string2_WDBypass_offensive_tool_keyword = "\"Starting WD Disable\"" nocase ascii wide
                        $string3_WDBypass_offensive_tool_keyword = /\\DisableWD\.7z/ nocase ascii wide
                        $string4_WDBypass_offensive_tool_keyword = /\\Silent\.7z/ nocase ascii wide
                        $string5_WDBypass_offensive_tool_keyword = "A220F564-41CB-46F5-9938-FEFD87819771" nocase ascii wide
                        $string6_WDBypass_offensive_tool_keyword = "F1E836C1-2279-49B3-84CC-ED8B048FCC44" nocase ascii wide
                        $string7_WDBypass_offensive_tool_keyword = /https\:\/\/bitbucket\.org\/evilgreyswork\// nocase ascii wide

    condition:
        any of them
}