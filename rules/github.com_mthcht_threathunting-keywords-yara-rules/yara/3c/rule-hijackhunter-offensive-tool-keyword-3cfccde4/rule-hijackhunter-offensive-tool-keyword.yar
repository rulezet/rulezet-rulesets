rule rule_HijackHunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HijackHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HijackHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HijackHunter_offensive_tool_keyword = "/HijackHunter/" nocase ascii wide
                        $string2_HijackHunter_offensive_tool_keyword = /\\HijackHunter\\/ nocase ascii wide
                        $string3_HijackHunter_offensive_tool_keyword = /dll.{0,1000}\s\[HIJACKABLE\]/ nocase ascii wide
                        $string4_HijackHunter_offensive_tool_keyword = /HijackHunter\.csproj/ nocase ascii wide
                        $string5_HijackHunter_offensive_tool_keyword = /HijackHunter\.exe/ nocase ascii wide
                        $string6_HijackHunter_offensive_tool_keyword = "hijackProgDirMissingDll" nocase ascii wide

    condition:
        any of them
}