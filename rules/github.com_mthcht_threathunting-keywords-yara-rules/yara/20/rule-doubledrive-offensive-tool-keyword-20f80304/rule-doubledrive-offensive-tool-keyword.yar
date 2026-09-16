rule rule_DoubleDrive_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DoubleDrive' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoubleDrive"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DoubleDrive_offensive_tool_keyword = " --command-uac-bypass" nocase ascii wide
                        $string2_DoubleDrive_offensive_tool_keyword = /\sendpoint_takeover\.py/ nocase ascii wide
                        $string3_DoubleDrive_offensive_tool_keyword = /\sfollow_attacker_commands\.py/ nocase ascii wide
                        $string4_DoubleDrive_offensive_tool_keyword = /\sgoogle_drive_doubledrive\.py/ nocase ascii wide
                        $string5_DoubleDrive_offensive_tool_keyword = /\sRANSOM_NOTE\.txt/ nocase ascii wide
                        $string6_DoubleDrive_offensive_tool_keyword = " --ransom-note-name " nocase ascii wide
                        $string7_DoubleDrive_offensive_tool_keyword = " --remote-ransomware" nocase ascii wide
                        $string8_DoubleDrive_offensive_tool_keyword = " --sharepoint-replacement-exe-path " nocase ascii wide
                        $string9_DoubleDrive_offensive_tool_keyword = " --temp-email --target-paths " nocase ascii wide
                        $string10_DoubleDrive_offensive_tool_keyword = /\svictim_info_key\.py/ nocase ascii wide
                        $string11_DoubleDrive_offensive_tool_keyword = "\"PAY ME MONEY\"" nocase ascii wide
                        $string12_DoubleDrive_offensive_tool_keyword = /\\"RANSOM_NOTE\.txt\\"/ nocase ascii wide
                        $string13_DoubleDrive_offensive_tool_keyword = /\/DoubleDrive\.git/ nocase ascii wide
                        $string14_DoubleDrive_offensive_tool_keyword = /\/DoubleDrive\-main\.zip/ nocase ascii wide
                        $string15_DoubleDrive_offensive_tool_keyword = /\/endpoint_takeover\.py/ nocase ascii wide
                        $string16_DoubleDrive_offensive_tool_keyword = /\/follow_attacker_commands\.py/ nocase ascii wide
                        $string17_DoubleDrive_offensive_tool_keyword = /\/google_drive_doubledrive\.py/ nocase ascii wide
                        $string18_DoubleDrive_offensive_tool_keyword = /\/victim_info_key\.py/ nocase ascii wide
                        $string19_DoubleDrive_offensive_tool_keyword = /\\DoubleDrive\-main\.zip/ nocase ascii wide
                        $string20_DoubleDrive_offensive_tool_keyword = /\\endpoint_takeover\.py/ nocase ascii wide
                        $string21_DoubleDrive_offensive_tool_keyword = /\\follow_attacker_commands\.py/ nocase ascii wide
                        $string22_DoubleDrive_offensive_tool_keyword = /\\google_drive_doubledrive\.py/ nocase ascii wide
                        $string23_DoubleDrive_offensive_tool_keyword = /\\RANSOM_NOTE\.txt/ nocase ascii wide
                        $string24_DoubleDrive_offensive_tool_keyword = /\\victim_info_key\.py/ nocase ascii wide
                        $string25_DoubleDrive_offensive_tool_keyword = "055d93807dbb92adac4bfd63349ac634e7a214712115656f00d9a1750d98da52" nocase ascii wide
                        $string26_DoubleDrive_offensive_tool_keyword = "4d7424482e96e9326182ad86bbe68a0f7b9da63d7508552649f05a18848d4bad" nocase ascii wide
                        $string27_DoubleDrive_offensive_tool_keyword = "5eb8024e00c244de2646f2b338be02e7a6475637fd04894a3e13d37783b0d693" nocase ascii wide
                        $string28_DoubleDrive_offensive_tool_keyword = "b310173eac2770b78f821900614fc900502e4cbe506daa55cd1baae3f22fa4cf" nocase ascii wide
                        $string29_DoubleDrive_offensive_tool_keyword = /cloud_drive_ransomware\.py/ nocase ascii wide
                        $string30_DoubleDrive_offensive_tool_keyword = /doubledrive\.cloud_drive\.google_drive\.google_drive/ nocase ascii wide
                        $string31_DoubleDrive_offensive_tool_keyword = /doubledrive\.cloud_ransomware/ nocase ascii wide
                        $string32_DoubleDrive_offensive_tool_keyword = /doubledrive\.endpoint_takeover_utils/ nocase ascii wide
                        $string33_DoubleDrive_offensive_tool_keyword = "eb2bcc1bc9b6802b3869f6343b0fcbe72f3d1642abbc34e0758122e6510c2f4a" nocase ascii wide
                        $string34_DoubleDrive_offensive_tool_keyword = /endpoint_takeover\.exe/ nocase ascii wide
                        $string35_DoubleDrive_offensive_tool_keyword = "f3b57e4b17458688b689824705327c1e854a796a4e027b6e34855627e79454c0" nocase ascii wide
                        $string36_DoubleDrive_offensive_tool_keyword = /follow_attacker_commands\.exe/ nocase ascii wide
                        $string37_DoubleDrive_offensive_tool_keyword = /follow_attacker_commands\.py/ nocase ascii wide
                        $string38_DoubleDrive_offensive_tool_keyword = /google_drive_doubledrive\.exe/ nocase ascii wide
                        $string39_DoubleDrive_offensive_tool_keyword = /google_drive_ransomware\.py/ nocase ascii wide
                        $string40_DoubleDrive_offensive_tool_keyword = /https\:\/\/api\.onedrive\.com\/v1\.0\/drives\/me\/items\/root\:\{onedrive_file_path\}\:\/oneDrive\.createUploadSession/ nocase ascii wide
                        $string41_DoubleDrive_offensive_tool_keyword = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=getDomainList/ nocase ascii wide
                        $string42_DoubleDrive_offensive_tool_keyword = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=getMessages\&login\=/ nocase ascii wide
                        $string43_DoubleDrive_offensive_tool_keyword = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=readMessage\&login\=/ nocase ascii wide
                        $string44_DoubleDrive_offensive_tool_keyword = /onedrive_doubledrive\.exe/ nocase ascii wide
                        $string45_DoubleDrive_offensive_tool_keyword = /onedrive_doubledrive\.py/ nocase ascii wide
                        $string46_DoubleDrive_offensive_tool_keyword = /onedrive_ransomware\.py/ nocase ascii wide
                        $string47_DoubleDrive_offensive_tool_keyword = /OneDriveRansomware\(CloudDriveRansomware\)/ nocase ascii wide
                        $string48_DoubleDrive_offensive_tool_keyword = "SafeBreach-Labs/DoubleDrive" nocase ascii wide
                        $string49_DoubleDrive_offensive_tool_keyword = "save the Fernet encryption/decryption key " nocase ascii wide
                        $string50_DoubleDrive_offensive_tool_keyword = "vssadmin delete shadows /all /quiet" nocase ascii wide

    condition:
        any of them
}