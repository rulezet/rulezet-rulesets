rule rule_ntdlll_unhooking_collection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntdlll-unhooking-collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdlll-unhooking-collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ntdlll_unhooking_collection_offensive_tool_keyword = "/ntdlll-unhooking-collection" nocase ascii wide
                        $string2_ntdlll_unhooking_collection_offensive_tool_keyword = /\\ntdlll\-unhooking\-collection/ nocase ascii wide
                        $string3_ntdlll_unhooking_collection_offensive_tool_keyword = "0472A393-9503-491D-B6DA-FA47CD567EDE" nocase ascii wide
                        $string4_ntdlll_unhooking_collection_offensive_tool_keyword = "1C5EDA8C-D27F-44A4-A156-6F863477194D" nocase ascii wide
                        $string5_ntdlll_unhooking_collection_offensive_tool_keyword = "4DE43724-3851-4376-BB6C-EA15CF500C44" nocase ascii wide
                        $string6_ntdlll_unhooking_collection_offensive_tool_keyword = "DA230B64-14EA-4D49-96E1-FA5EFED9010B" nocase ascii wide
                        $string7_ntdlll_unhooking_collection_offensive_tool_keyword = /Ntdll_SusProcess\./ nocase ascii wide
                        $string8_ntdlll_unhooking_collection_offensive_tool_keyword = /RemoteNTDLL\.cpp/ nocase ascii wide
                        $string9_ntdlll_unhooking_collection_offensive_tool_keyword = /RemoteNTDLL\.exe/ nocase ascii wide
                        $string10_ntdlll_unhooking_collection_offensive_tool_keyword = /UnhookingKnownDlls\./ nocase ascii wide
                        $string11_ntdlll_unhooking_collection_offensive_tool_keyword = /UnhookingNtdll_disk\./ nocase ascii wide

    condition:
        any of them
}