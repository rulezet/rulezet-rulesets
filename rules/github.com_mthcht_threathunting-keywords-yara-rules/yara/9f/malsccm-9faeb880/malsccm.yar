rule MalSCCM
{
    meta:
        description = "Detection patterns for the tool 'MalSCCM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MalSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\sapp\s\/create\s\/name\:.{0,1000}\s\/uncpath\:.{0,1000}\\\\/ nocase ascii wide
                        $string2 = /\.exe\sapp\s\/deploy\s\/name\:.{0,1000}\s\/groupname\:.{0,1000}\s\/assignmentname\:/ nocase ascii wide
                        $string3 = /\/MalSCCM\.git/ nocase ascii wide
                        $string4 = /\/MalSCCM\.sln/ nocase ascii wide
                        $string5 = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" nocase ascii wide
                        $string6 = "Action: Locating SCCM Management Servers" nocase ascii wide
                        $string7 = "Action: Locating SCCM Servers in Registry" nocase ascii wide
                        $string8 = /MalSCCM\.exe/ nocase ascii wide
                        $string9 = "MalSCCM-main" nocase ascii wide
                        $string10 = "nettitude/MalSCCM" nocase ascii wide

    condition:
        any of them
}