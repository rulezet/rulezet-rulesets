rule DFSCoerce
{
    meta:
        description = "Detection patterns for the tool 'DFSCoerce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DFSCoerce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DFSCoerce\.git/ nocase ascii wide
                        $string2 = /coerce\smachine\saccount\sauthentication\svia\sMS\-DFSNM\sNetrDfsRemoveStdRoot\(\)/ nocase ascii wide
                        $string3 = /dfscoerce\.py/ nocase ascii wide
                        $string4 = "DFSCoerce-main" nocase ascii wide
                        $string5 = "Wh04m1001/DFSCoerce" nocase ascii wide

    condition:
        any of them
}