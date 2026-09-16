rule rule_DFSCoerce_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DFSCoerce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DFSCoerce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DFSCoerce_offensive_tool_keyword = /\/DFSCoerce\.git/ nocase ascii wide
                        $string2_DFSCoerce_offensive_tool_keyword = /coerce\smachine\saccount\sauthentication\svia\sMS\-DFSNM\sNetrDfsRemoveStdRoot\(\)/ nocase ascii wide
                        $string3_DFSCoerce_offensive_tool_keyword = /dfscoerce\.py/ nocase ascii wide
                        $string4_DFSCoerce_offensive_tool_keyword = "DFSCoerce-main" nocase ascii wide
                        $string5_DFSCoerce_offensive_tool_keyword = "Wh04m1001/DFSCoerce" nocase ascii wide

    condition:
        any of them
}