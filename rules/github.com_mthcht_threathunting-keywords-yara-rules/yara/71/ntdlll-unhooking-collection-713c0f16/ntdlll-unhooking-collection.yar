rule ntdlll_unhooking_collection
{
    meta:
        description = "Detection patterns for the tool 'ntdlll-unhooking-collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdlll-unhooking-collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ntdlll-unhooking-collection" nocase ascii wide
                        $string2 = /\\ntdlll\-unhooking\-collection/ nocase ascii wide
                        $string3 = "0472A393-9503-491D-B6DA-FA47CD567EDE" nocase ascii wide
                        $string4 = "1C5EDA8C-D27F-44A4-A156-6F863477194D" nocase ascii wide
                        $string5 = "4DE43724-3851-4376-BB6C-EA15CF500C44" nocase ascii wide
                        $string6 = "DA230B64-14EA-4D49-96E1-FA5EFED9010B" nocase ascii wide
                        $string7 = /Ntdll_SusProcess\./ nocase ascii wide
                        $string8 = /RemoteNTDLL\.cpp/ nocase ascii wide
                        $string9 = /RemoteNTDLL\.exe/ nocase ascii wide
                        $string10 = /UnhookingKnownDlls\./ nocase ascii wide
                        $string11 = /UnhookingNtdll_disk\./ nocase ascii wide

    condition:
        any of them
}