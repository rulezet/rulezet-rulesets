rule rule_UnhookingPatch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UnhookingPatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnhookingPatch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UnhookingPatch_offensive_tool_keyword = /\sbin2mac\.py/ nocase ascii wide
                        $string2_UnhookingPatch_offensive_tool_keyword = /\/PatchingAPI\.cpp/ nocase ascii wide
                        $string3_UnhookingPatch_offensive_tool_keyword = /\/PatchingAPI\.exe/ nocase ascii wide
                        $string4_UnhookingPatch_offensive_tool_keyword = /\/UnhookingPatch\.git/ nocase ascii wide
                        $string5_UnhookingPatch_offensive_tool_keyword = /\/UnhookingPatch\.git/ nocase ascii wide
                        $string6_UnhookingPatch_offensive_tool_keyword = /\[\-\]\sNtAllocateVirtualMemory\sHooked/ nocase ascii wide
                        $string7_UnhookingPatch_offensive_tool_keyword = /\[\-\]\sNtProtectVirtualMemory\sHooked/ nocase ascii wide
                        $string8_UnhookingPatch_offensive_tool_keyword = /\[\-\]\sNtWaitForSingleObject\sHooked/ nocase ascii wide
                        $string9_UnhookingPatch_offensive_tool_keyword = /\[\+\]\sNtAllocateVirtualMemory\sNot\sHooked/ nocase ascii wide
                        $string10_UnhookingPatch_offensive_tool_keyword = /\[\+\]\sNtProtectVirtualMemory\sNot\sHooked/ nocase ascii wide
                        $string11_UnhookingPatch_offensive_tool_keyword = /\[\+\]\sNtWaitForSingleObject\sNot\sHooked/ nocase ascii wide
                        $string12_UnhookingPatch_offensive_tool_keyword = /\\PatchingAPI\.cpp/ nocase ascii wide
                        $string13_UnhookingPatch_offensive_tool_keyword = /\\PatchingAPI\.cpp/ nocase ascii wide
                        $string14_UnhookingPatch_offensive_tool_keyword = /\\PatchingAPI\.exe/ nocase ascii wide
                        $string15_UnhookingPatch_offensive_tool_keyword = /\\UnhookingPatch\\bin2mac\.py/ nocase ascii wide
                        $string16_UnhookingPatch_offensive_tool_keyword = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase ascii wide
                        $string17_UnhookingPatch_offensive_tool_keyword = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase ascii wide
                        $string18_UnhookingPatch_offensive_tool_keyword = /bin2mac\.py\s.{0,1000}\.bin/ nocase ascii wide
                        $string19_UnhookingPatch_offensive_tool_keyword = /PatchingAPI\.exe/ nocase ascii wide
                        $string20_UnhookingPatch_offensive_tool_keyword = "SaadAhla/UnhookingPatch" nocase ascii wide
                        $string21_UnhookingPatch_offensive_tool_keyword = "TheD1rkMtr/UnhookingPatch" nocase ascii wide
                        $string22_UnhookingPatch_offensive_tool_keyword = "UnhookingPatch-main" nocase ascii wide
                        $string23_UnhookingPatch_offensive_tool_keyword = "UnhookingPatch-main" nocase ascii wide

    condition:
        any of them
}