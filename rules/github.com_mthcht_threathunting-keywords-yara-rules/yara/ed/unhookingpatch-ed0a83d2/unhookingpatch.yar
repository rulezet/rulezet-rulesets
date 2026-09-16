rule UnhookingPatch
{
    meta:
        description = "Detection patterns for the tool 'UnhookingPatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnhookingPatch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbin2mac\.py/ nocase ascii wide
                        $string2 = /\/PatchingAPI\.cpp/ nocase ascii wide
                        $string3 = /\/PatchingAPI\.exe/ nocase ascii wide
                        $string4 = /\/UnhookingPatch\.git/ nocase ascii wide
                        $string5 = /\/UnhookingPatch\.git/ nocase ascii wide
                        $string6 = /\[\-\]\sNtAllocateVirtualMemory\sHooked/ nocase ascii wide
                        $string7 = /\[\-\]\sNtProtectVirtualMemory\sHooked/ nocase ascii wide
                        $string8 = /\[\-\]\sNtWaitForSingleObject\sHooked/ nocase ascii wide
                        $string9 = /\[\+\]\sNtAllocateVirtualMemory\sNot\sHooked/ nocase ascii wide
                        $string10 = /\[\+\]\sNtProtectVirtualMemory\sNot\sHooked/ nocase ascii wide
                        $string11 = /\[\+\]\sNtWaitForSingleObject\sNot\sHooked/ nocase ascii wide
                        $string12 = /\\PatchingAPI\.cpp/ nocase ascii wide
                        $string13 = /\\PatchingAPI\.cpp/ nocase ascii wide
                        $string14 = /\\PatchingAPI\.exe/ nocase ascii wide
                        $string15 = /\\UnhookingPatch\\bin2mac\.py/ nocase ascii wide
                        $string16 = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase ascii wide
                        $string17 = "81E60DC6-694E-4F51-88FA-6F481B9A4208" nocase ascii wide
                        $string18 = /bin2mac\.py\s.{0,1000}\.bin/ nocase ascii wide
                        $string19 = /PatchingAPI\.exe/ nocase ascii wide
                        $string20 = "SaadAhla/UnhookingPatch" nocase ascii wide
                        $string21 = "TheD1rkMtr/UnhookingPatch" nocase ascii wide
                        $string22 = "UnhookingPatch-main" nocase ascii wide
                        $string23 = "UnhookingPatch-main" nocase ascii wide

    condition:
        any of them
}