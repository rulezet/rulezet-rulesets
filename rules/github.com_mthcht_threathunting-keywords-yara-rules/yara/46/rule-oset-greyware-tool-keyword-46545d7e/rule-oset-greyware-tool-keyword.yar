rule rule_oset_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'oset' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "oset"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_oset_greyware_tool_keyword = /\sOfflineSamTool\.h/ nocase ascii wide
                        $string2_oset_greyware_tool_keyword = /\/OfflineSamTool\.exe/ nocase ascii wide
                        $string3_oset_greyware_tool_keyword = /\/oset\.exe/ nocase ascii wide
                        $string4_oset_greyware_tool_keyword = /\/oset\.zip/ nocase ascii wide
                        $string5_oset_greyware_tool_keyword = /\\OfflineSamTool\.exe/ nocase ascii wide
                        $string6_oset_greyware_tool_keyword = /\\OfflineSamTool\.h/ nocase ascii wide
                        $string7_oset_greyware_tool_keyword = /\\oset\.exe/ nocase ascii wide
                        $string8_oset_greyware_tool_keyword = /\\oset\.zip/ nocase ascii wide
                        $string9_oset_greyware_tool_keyword = /\\Root\\InventoryApplicationFile\\offlinesamtool/ nocase ascii wide
                        $string10_oset_greyware_tool_keyword = ">Open Source Developer, Grzegorz Tworek<" nocase ascii wide
                        $string11_oset_greyware_tool_keyword = "03a3b39dd1b9bfb7421e4ba555ca9669b0e3ca7d993ce921d249493aee23b484" nocase ascii wide
                        $string12_oset_greyware_tool_keyword = "5f87b4ab00f09c64f4d30fcfbf19e9e6945971c74d28370c720e52b83f7decf3" nocase ascii wide
                        $string13_oset_greyware_tool_keyword = "62440D3B8BE22B9353AC1374CC6ED1FAF4476908FE6D8E9FBD3AA62004EFEF3E" nocase ascii wide
                        $string14_oset_greyware_tool_keyword = "66092d1e08e55e35b60dc348f2f59d69c0768a09ce411a50fc0d161bfab3303d" nocase ascii wide
                        $string15_oset_greyware_tool_keyword = "776b64a95ccc334446805d680288c7ac35f1e938ee43115c1911f1c2fed27312" nocase ascii wide
                        $string16_oset_greyware_tool_keyword = "a5e57662131399ad586e4b5c4a942bc9029104331953fdbdbfd6e8a0cdad9ccc" nocase ascii wide
                        $string17_oset_greyware_tool_keyword = "b10cfda1-f24f-441b-8f43-80cb93e786ec" nocase ascii wide
                        $string18_oset_greyware_tool_keyword = "C50B26839FCDA18B4DB6560EB826E94C" nocase ascii wide
                        $string19_oset_greyware_tool_keyword = "Cannot enumerate SAM objects" nocase ascii wide
                        $string20_oset_greyware_tool_keyword = "Error converting offlinesam path" nocase ascii wide
                        $string21_oset_greyware_tool_keyword = "f14052ce01a373effaf1c74eeed9ccda8ac4f6cf3407727d4a5871df9f195f57" nocase ascii wide
                        $string22_oset_greyware_tool_keyword = "f9ac9d3510fb8c2a50b03605454263af27cf68ef4f27458c03b12607a0f8ebd3" nocase ascii wide
                        $string23_oset_greyware_tool_keyword = "Offline SAM Editing Tool - Changed" nocase ascii wide
                        $string24_oset_greyware_tool_keyword = "Offline SAM Editing Tool" nocase ascii wide
                        $string25_oset_greyware_tool_keyword = "Offline SAM loaded successfully" nocase ascii wide
                        $string26_oset_greyware_tool_keyword = /Offline\sSAM\sTool\\r\\nUse\swith\scaution\!/ nocase ascii wide
                        $string27_oset_greyware_tool_keyword = "Open Source Developer, Grzegorz Tworek" nocase ascii wide
                        $string28_oset_greyware_tool_keyword = /reg\.exe\squery\shklm\s\^\|\sfindstr\s\/i\s\\\\OFFLINE\'/ nocase ascii wide
                        $string29_oset_greyware_tool_keyword = /reg\.exe\squery\shklm\s\^\|\sfindstr\s\/i\s\\OFFLINE/ nocase ascii wide
                        $string30_oset_greyware_tool_keyword = "SamOfflineConnect" nocase ascii wide
                        $string31_oset_greyware_tool_keyword = "SamOfflineEnumerateDomainsInSamServer" nocase ascii wide
                        $string32_oset_greyware_tool_keyword = "SamOfflineEnumerateUsersInDomain2" nocase ascii wide
                        $string33_oset_greyware_tool_keyword = "SamOfflineGetMembersInAlias" nocase ascii wide
                        $string34_oset_greyware_tool_keyword = "SamOfflineLookupDomainInSamServer" nocase ascii wide
                        $string35_oset_greyware_tool_keyword = "SamOfflineOpenDomain" nocase ascii wide
                        $string36_oset_greyware_tool_keyword = "SamOfflineOpenUser" nocase ascii wide
                        $string37_oset_greyware_tool_keyword = "SamOfflineQueryInformationAlias" nocase ascii wide
                        $string38_oset_greyware_tool_keyword = "SamOfflineQueryInformationUser" nocase ascii wide
                        $string39_oset_greyware_tool_keyword = "SamOfflineRemoveMemberFromAlias" nocase ascii wide
                        $string40_oset_greyware_tool_keyword = "SamOfflineRidToSid" nocase ascii wide
                        $string41_oset_greyware_tool_keyword = "SamOfflineSetInformationAlias" nocase ascii wide
                        $string42_oset_greyware_tool_keyword = /stderr\.pl\/oset/ nocase ascii wide

    condition:
        any of them
}