rule rule_FruityC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FruityC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FruityC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FruityC2_offensive_tool_keyword = " -DumpCreds -ComputerName " nocase ascii wide
                        $string2_FruityC2_offensive_tool_keyword = " -ServiceName VulnSVC " nocase ascii wide
                        $string3_FruityC2_offensive_tool_keyword = /\/fruityc2\.crt/
                        $string4_FruityC2_offensive_tool_keyword = /\/FruityC2\.git/ nocase ascii wide
                        $string5_FruityC2_offensive_tool_keyword = /\/fruityc2\.key/
                        $string6_FruityC2_offensive_tool_keyword = /\/fruityc2\.pem/
                        $string7_FruityC2_offensive_tool_keyword = /\/FruityC2\/archive\/master\.zip/ nocase ascii wide
                        $string8_FruityC2_offensive_tool_keyword = "/FruityC2/releases/" nocase ascii wide
                        $string9_FruityC2_offensive_tool_keyword = "/FruityC2-Client" nocase ascii wide
                        $string10_FruityC2_offensive_tool_keyword = /\\FruityC2\-Client/ nocase ascii wide
                        $string11_FruityC2_offensive_tool_keyword = /\\ps_encoder\.py/ nocase ascii wide
                        $string12_FruityC2_offensive_tool_keyword = /\\ps_proxy\.ps1/ nocase ascii wide
                        $string13_FruityC2_offensive_tool_keyword = /\\ps_stager\.ps1/ nocase ascii wide
                        $string14_FruityC2_offensive_tool_keyword = /\\PSReflect\.psm1/ nocase ascii wide
                        $string15_FruityC2_offensive_tool_keyword = "<H1>PowerUp report for " nocase ascii wide
                        $string16_FruityC2_offensive_tool_keyword = "<H2>Vulnerabl Schasks" nocase ascii wide
                        $string17_FruityC2_offensive_tool_keyword = "028648d9410d8aaf65b7cb4999999947b55f8aa4db3ec24ff82b601b77ecc335" nocase ascii wide
                        $string18_FruityC2_offensive_tool_keyword = "069a9a0aece20ae241fe75e4ba6e1338f8292bf9510182883f649a32fe27604c" nocase ascii wide
                        $string19_FruityC2_offensive_tool_keyword = "21fff74c2464be8072328345721555138aed7e15adc531ae4f244820a0f3061f" nocase ascii wide
                        $string20_FruityC2_offensive_tool_keyword = "2e0680b916b117d6eff7e621212b7ac6f28c41b95a3fc18b91b13922e3e2e72f" nocase ascii wide
                        $string21_FruityC2_offensive_tool_keyword = "39f719f490cdea6b7566c0ad99a6c70b6d241f80328a82a403f33468a91744f2" nocase ascii wide
                        $string22_FruityC2_offensive_tool_keyword = "3a87abf646b679217d7c67e45c5df4bac7b3ea9f5e33ccd7ad82b964d0bc73a7" nocase ascii wide
                        $string23_FruityC2_offensive_tool_keyword = "40b10d676e40a4c5c006f2d8b92cd5fa069b83348612d052e626e7792b4edbf7" nocase ascii wide
                        $string24_FruityC2_offensive_tool_keyword = "4260354c3960e04e73b36289099665ce1cb839d1c56696639e782643c98dbe7b" nocase ascii wide
                        $string25_FruityC2_offensive_tool_keyword = "488785c691425b7cb3c355b1ae38a0527faf339f68a3536f34e1ee10c627790c" nocase ascii wide
                        $string26_FruityC2_offensive_tool_keyword = "4f5f8bd4df664f10dbd919129bbf7d8c6c8a02da74b36a20c322b5a1ce257249" nocase ascii wide
                        $string27_FruityC2_offensive_tool_keyword = "5241f01eb654fe100e0c2a973b7f2443e7bcd914e5b388cc07031871a7d4d199" nocase ascii wide
                        $string28_FruityC2_offensive_tool_keyword = "55b47d76298d6f56ea19a06c6bab41145675717159890d4787fe83c8785bbf23" nocase ascii wide
                        $string29_FruityC2_offensive_tool_keyword = "5f346d82d780b573ffd6e4ae1051dd96d10d5141d17535d5538ae8713096085b" nocase ascii wide
                        $string30_FruityC2_offensive_tool_keyword = "6cc72a74c01d04cf06cca303ba6a584a4261829d88fde64592e5a04cb0a16522" nocase ascii wide
                        $string31_FruityC2_offensive_tool_keyword = "7af03cf989ce48137cd2b74c1020fc42241d7dea7ffaf6ff67f16a23a302ad80" nocase ascii wide
                        $string32_FruityC2_offensive_tool_keyword = "99f14934d82a3db78f0f68017c079ec04dedddc5890bf5ce5194dd30801f779d" nocase ascii wide
                        $string33_FruityC2_offensive_tool_keyword = "a71ca78d1c4b0dc8d6c35c883b18034a5b505886cc74fed0003c5e095494b1c8" nocase ascii wide
                        $string34_FruityC2_offensive_tool_keyword = "adaptivethreat/Empire" nocase ascii wide
                        $string35_FruityC2_offensive_tool_keyword = "b4af4df46eb9a169f197c093325d983db5dc0ab1eb6bd7aa67458e4f48c2e0b2" nocase ascii wide
                        $string36_FruityC2_offensive_tool_keyword = /Create\sSSL\scertificate\s\(FruityC2\)/ nocase ascii wide
                        $string37_FruityC2_offensive_tool_keyword = "dec9c3346c770a93bd7f1fb1b891100d806ecc70f1c5da84ea001aa0efb3694d" nocase ascii wide
                        $string38_FruityC2_offensive_tool_keyword = "Downloading AD-Recon PS scripts" nocase ascii wide
                        $string39_FruityC2_offensive_tool_keyword = "Downloading Empire PS scripts" nocase ascii wide
                        $string40_FruityC2_offensive_tool_keyword = "Downloading FruityC2" nocase ascii wide
                        $string41_FruityC2_offensive_tool_keyword = "Downloading Nishang PS scripts" nocase ascii wide
                        $string42_FruityC2_offensive_tool_keyword = "Downloading PowerSploit PS scripts" nocase ascii wide
                        $string43_FruityC2_offensive_tool_keyword = "e1966d7c2abe5f6f610c745858ab19a48b1b4ee7db738e15f4bb8b1009f38eb9" nocase ascii wide
                        $string44_FruityC2_offensive_tool_keyword = "e35cdc81954fb9701b5fd2f79300a5a6b2dd018e82aa733727a734b08ddd9715" nocase ascii wide
                        $string45_FruityC2_offensive_tool_keyword = "eeba4c8ec806378fecc51fb7ffe3b48c5fa57108330b822043494cc4cea99d89" nocase ascii wide
                        $string46_FruityC2_offensive_tool_keyword = /FruityC2\.py/ nocase ascii wide
                        $string47_FruityC2_offensive_tool_keyword = /Get\-ExploitableSystem\.psm1/ nocase ascii wide
                        $string48_FruityC2_offensive_tool_keyword = /Get\-ExploitableSystems\.psm1/ nocase ascii wide
                        $string49_FruityC2_offensive_tool_keyword = /Get\-PassHashes\.ps1/ nocase ascii wide
                        $string50_FruityC2_offensive_tool_keyword = /Get\-Screenshot\.ps1/ nocase ascii wide
                        $string51_FruityC2_offensive_tool_keyword = /Get\-SPN\-FruityC2\.ps1/ nocase ascii wide
                        $string52_FruityC2_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\:50000\/payload\/upload/ nocase ascii wide
                        $string53_FruityC2_offensive_tool_keyword = "Invoke-ACLScanner" nocase ascii wide
                        $string54_FruityC2_offensive_tool_keyword = "Invoke-CheckLocalAdminAccess -ComputerName " nocase ascii wide
                        $string55_FruityC2_offensive_tool_keyword = "Invoke-EnumerateLocalAdmin" nocase ascii wide
                        $string56_FruityC2_offensive_tool_keyword = "Invoke-FileFinder -ShareList " nocase ascii wide
                        $string57_FruityC2_offensive_tool_keyword = "Invoke-FruityC2" nocase ascii wide
                        $string58_FruityC2_offensive_tool_keyword = "Invoke-ImpersonateUser" nocase ascii wide
                        $string59_FruityC2_offensive_tool_keyword = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
                        $string60_FruityC2_offensive_tool_keyword = "Invoke-PatchDll -DllBytes " nocase ascii wide
                        $string61_FruityC2_offensive_tool_keyword = "invoke-reflectivedllinjection-ps1" nocase ascii wide
                        $string62_FruityC2_offensive_tool_keyword = "Invoke-ServiceAbuse" nocase ascii wide
                        $string63_FruityC2_offensive_tool_keyword = "Invoke-StealthUserHunter " nocase ascii wide
                        $string64_FruityC2_offensive_tool_keyword = /Invoke\-TokenManipulation\.ps1/ nocase ascii wide
                        $string65_FruityC2_offensive_tool_keyword = /PostExploitation\.psm1/ nocase ascii wide
                        $string66_FruityC2_offensive_tool_keyword = /powershell\-import\s\/var\/www\/ps\/.{0,1000}\.ps1/ nocase ascii wide
                        $string67_FruityC2_offensive_tool_keyword = /PowerUp\.ps1/ nocase ascii wide
                        $string68_FruityC2_offensive_tool_keyword = /PowerView\.ps1/ nocase ascii wide
                        $string69_FruityC2_offensive_tool_keyword = "PyroTek3/PowerShell-AD-Recon" nocase ascii wide
                        $string70_FruityC2_offensive_tool_keyword = "samratashok/nishang" nocase ascii wide
                        $string71_FruityC2_offensive_tool_keyword = /standard\:\:base64.{0,1000}kerberos\:\:list\s\/export/ nocase ascii wide
                        $string72_FruityC2_offensive_tool_keyword = "Write-HijackDll -OutputFile" nocase ascii wide
                        $string73_FruityC2_offensive_tool_keyword = "xtr4nge/FruityC2" nocase ascii wide

    condition:
        any of them
}