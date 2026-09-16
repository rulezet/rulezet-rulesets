rule rule_Imminent_Monitor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Imminent-Monitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Imminent-Monitor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Imminent_Monitor_offensive_tool_keyword = /\/Imminent\sMonitor\s3\.9\.exe/ nocase ascii wide
                        $string2_Imminent_Monitor_offensive_tool_keyword = /\/ImminentMonitor\.exe/ nocase ascii wide
                        $string3_Imminent_Monitor_offensive_tool_keyword = /\\Imminent\sMonitor\s3\.9\.exe/ nocase ascii wide
                        $string4_Imminent_Monitor_offensive_tool_keyword = /\\ImminentMonitor\.exe/ nocase ascii wide
                        $string5_Imminent_Monitor_offensive_tool_keyword = ">Imminent Monitor<" nocase ascii wide
                        $string6_Imminent_Monitor_offensive_tool_keyword = "6c7b6faf5a493f036e6b69a0f4c9c7f1b86c068a56ce4d8d9a92c8ebde0eae99" nocase ascii wide
                        $string7_Imminent_Monitor_offensive_tool_keyword = "9078149dc6ee62aea91749ba2db9aba15c9518f92bfe709b3bba8523f92cd2e8" nocase ascii wide
                        $string8_Imminent_Monitor_offensive_tool_keyword = "Indestructible7/Imminent-Monitor" nocase ascii wide

    condition:
        any of them
}