rule rule_MalSCCM_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MalSCCM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MalSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MalSCCM_offensive_tool_keyword = /\.exe\sapp\s\/create\s\/name\:.{0,1000}\s\/uncpath\:.{0,1000}\\\\/ nocase ascii wide
                        $string2_MalSCCM_offensive_tool_keyword = /\.exe\sapp\s\/deploy\s\/name\:.{0,1000}\s\/groupname\:.{0,1000}\s\/assignmentname\:/ nocase ascii wide
                        $string3_MalSCCM_offensive_tool_keyword = /\/MalSCCM\.git/ nocase ascii wide
                        $string4_MalSCCM_offensive_tool_keyword = /\/MalSCCM\.sln/ nocase ascii wide
                        $string5_MalSCCM_offensive_tool_keyword = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" nocase ascii wide
                        $string6_MalSCCM_offensive_tool_keyword = "Action: Locating SCCM Management Servers" nocase ascii wide
                        $string7_MalSCCM_offensive_tool_keyword = "Action: Locating SCCM Servers in Registry" nocase ascii wide
                        $string8_MalSCCM_offensive_tool_keyword = /MalSCCM\.exe/ nocase ascii wide
                        $string9_MalSCCM_offensive_tool_keyword = "MalSCCM-main" nocase ascii wide
                        $string10_MalSCCM_offensive_tool_keyword = "nettitude/MalSCCM" nocase ascii wide

    condition:
        any of them
}