rule oset
{
    meta:
        description = "Detection patterns for the tool 'oset' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "oset"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sOfflineSamTool\.h/ nocase ascii wide
                        $string2 = /\/OfflineSamTool\.exe/ nocase ascii wide
                        $string3 = /\/oset\.exe/ nocase ascii wide
                        $string4 = /\/oset\.zip/ nocase ascii wide
                        $string5 = /\\OfflineSamTool\.exe/ nocase ascii wide
                        $string6 = /\\OfflineSamTool\.h/ nocase ascii wide
                        $string7 = /\\oset\.exe/ nocase ascii wide
                        $string8 = /\\oset\.zip/ nocase ascii wide
                        $string9 = /\\Root\\InventoryApplicationFile\\offlinesamtool/ nocase ascii wide
                        $string10 = ">Open Source Developer, Grzegorz Tworek<" nocase ascii wide
                        $string11 = "03a3b39dd1b9bfb7421e4ba555ca9669b0e3ca7d993ce921d249493aee23b484" nocase ascii wide
                        $string12 = "5f87b4ab00f09c64f4d30fcfbf19e9e6945971c74d28370c720e52b83f7decf3" nocase ascii wide
                        $string13 = "62440D3B8BE22B9353AC1374CC6ED1FAF4476908FE6D8E9FBD3AA62004EFEF3E" nocase ascii wide
                        $string14 = "66092d1e08e55e35b60dc348f2f59d69c0768a09ce411a50fc0d161bfab3303d" nocase ascii wide
                        $string15 = "776b64a95ccc334446805d680288c7ac35f1e938ee43115c1911f1c2fed27312" nocase ascii wide
                        $string16 = "a5e57662131399ad586e4b5c4a942bc9029104331953fdbdbfd6e8a0cdad9ccc" nocase ascii wide
                        $string17 = "b10cfda1-f24f-441b-8f43-80cb93e786ec" nocase ascii wide
                        $string18 = "C50B26839FCDA18B4DB6560EB826E94C" nocase ascii wide
                        $string19 = "Cannot enumerate SAM objects" nocase ascii wide
                        $string20 = "Error converting offlinesam path" nocase ascii wide
                        $string21 = "f14052ce01a373effaf1c74eeed9ccda8ac4f6cf3407727d4a5871df9f195f57" nocase ascii wide
                        $string22 = "f9ac9d3510fb8c2a50b03605454263af27cf68ef4f27458c03b12607a0f8ebd3" nocase ascii wide
                        $string23 = "Offline SAM Editing Tool - Changed" nocase ascii wide
                        $string24 = "Offline SAM Editing Tool" nocase ascii wide
                        $string25 = "Offline SAM loaded successfully" nocase ascii wide
                        $string26 = /Offline\sSAM\sTool\\r\\nUse\swith\scaution\!/ nocase ascii wide
                        $string27 = "Open Source Developer, Grzegorz Tworek" nocase ascii wide
                        $string28 = /reg\.exe\squery\shklm\s\^\|\sfindstr\s\/i\s\\\\OFFLINE\'/ nocase ascii wide
                        $string29 = /reg\.exe\squery\shklm\s\^\|\sfindstr\s\/i\s\\OFFLINE/ nocase ascii wide
                        $string30 = "SamOfflineConnect" nocase ascii wide
                        $string31 = "SamOfflineEnumerateDomainsInSamServer" nocase ascii wide
                        $string32 = "SamOfflineEnumerateUsersInDomain2" nocase ascii wide
                        $string33 = "SamOfflineGetMembersInAlias" nocase ascii wide
                        $string34 = "SamOfflineLookupDomainInSamServer" nocase ascii wide
                        $string35 = "SamOfflineOpenDomain" nocase ascii wide
                        $string36 = "SamOfflineOpenUser" nocase ascii wide
                        $string37 = "SamOfflineQueryInformationAlias" nocase ascii wide
                        $string38 = "SamOfflineQueryInformationUser" nocase ascii wide
                        $string39 = "SamOfflineRemoveMemberFromAlias" nocase ascii wide
                        $string40 = "SamOfflineRidToSid" nocase ascii wide
                        $string41 = "SamOfflineSetInformationAlias" nocase ascii wide
                        $string42 = /stderr\.pl\/oset/ nocase ascii wide

    condition:
        any of them
}