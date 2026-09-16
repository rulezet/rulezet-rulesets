rule rule_SharpSAMDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSAMDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSAMDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSAMDump_offensive_tool_keyword = /\/SharpSAMDump\.git/ nocase ascii wide
                        $string2_SharpSAMDump_offensive_tool_keyword = /\\SharpSAMDump\-main/ nocase ascii wide
                        $string3_SharpSAMDump_offensive_tool_keyword = ">SharpSAMDump<" nocase ascii wide
                        $string4_SharpSAMDump_offensive_tool_keyword = "158c0b33376d319848cffd69f20dc6e2dc93aa66ed71dffd6f0ee3803da70dd2" nocase ascii wide
                        $string5_SharpSAMDump_offensive_tool_keyword = "4FEAB888-F514-4F2E-A4F7-5989A86A69DE" nocase ascii wide
                        $string6_SharpSAMDump_offensive_tool_keyword = "f97334c71892acdc50380141f0c6144363b7a55a1fe5adf01543b2adbd2d7e44" nocase ascii wide
                        $string7_SharpSAMDump_offensive_tool_keyword = "jojonas/SharpSAMDump" nocase ascii wide
                        $string8_SharpSAMDump_offensive_tool_keyword = /SharpSAMDump\.exe/ nocase ascii wide

    condition:
        any of them
}