rule DoubleDrive
{
    meta:
        description = "Detection patterns for the tool 'DoubleDrive' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoubleDrive"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --command-uac-bypass" nocase ascii wide
                        $string2 = /\sendpoint_takeover\.py/ nocase ascii wide
                        $string3 = /\sfollow_attacker_commands\.py/ nocase ascii wide
                        $string4 = /\sgoogle_drive_doubledrive\.py/ nocase ascii wide
                        $string5 = /\sRANSOM_NOTE\.txt/ nocase ascii wide
                        $string6 = " --ransom-note-name " nocase ascii wide
                        $string7 = " --remote-ransomware" nocase ascii wide
                        $string8 = " --sharepoint-replacement-exe-path " nocase ascii wide
                        $string9 = " --temp-email --target-paths " nocase ascii wide
                        $string10 = /\svictim_info_key\.py/ nocase ascii wide
                        $string11 = "\"PAY ME MONEY\"" nocase ascii wide
                        $string12 = /\\"RANSOM_NOTE\.txt\\"/ nocase ascii wide
                        $string13 = /\/DoubleDrive\.git/ nocase ascii wide
                        $string14 = /\/DoubleDrive\-main\.zip/ nocase ascii wide
                        $string15 = /\/endpoint_takeover\.py/ nocase ascii wide
                        $string16 = /\/follow_attacker_commands\.py/ nocase ascii wide
                        $string17 = /\/google_drive_doubledrive\.py/ nocase ascii wide
                        $string18 = /\/victim_info_key\.py/ nocase ascii wide
                        $string19 = /\\DoubleDrive\-main\.zip/ nocase ascii wide
                        $string20 = /\\endpoint_takeover\.py/ nocase ascii wide
                        $string21 = /\\follow_attacker_commands\.py/ nocase ascii wide
                        $string22 = /\\google_drive_doubledrive\.py/ nocase ascii wide
                        $string23 = /\\RANSOM_NOTE\.txt/ nocase ascii wide
                        $string24 = /\\victim_info_key\.py/ nocase ascii wide
                        $string25 = "055d93807dbb92adac4bfd63349ac634e7a214712115656f00d9a1750d98da52" nocase ascii wide
                        $string26 = "4d7424482e96e9326182ad86bbe68a0f7b9da63d7508552649f05a18848d4bad" nocase ascii wide
                        $string27 = "5eb8024e00c244de2646f2b338be02e7a6475637fd04894a3e13d37783b0d693" nocase ascii wide
                        $string28 = "b310173eac2770b78f821900614fc900502e4cbe506daa55cd1baae3f22fa4cf" nocase ascii wide
                        $string29 = /cloud_drive_ransomware\.py/ nocase ascii wide
                        $string30 = /doubledrive\.cloud_drive\.google_drive\.google_drive/ nocase ascii wide
                        $string31 = /doubledrive\.cloud_ransomware/ nocase ascii wide
                        $string32 = /doubledrive\.endpoint_takeover_utils/ nocase ascii wide
                        $string33 = "eb2bcc1bc9b6802b3869f6343b0fcbe72f3d1642abbc34e0758122e6510c2f4a" nocase ascii wide
                        $string34 = /endpoint_takeover\.exe/ nocase ascii wide
                        $string35 = "f3b57e4b17458688b689824705327c1e854a796a4e027b6e34855627e79454c0" nocase ascii wide
                        $string36 = /follow_attacker_commands\.exe/ nocase ascii wide
                        $string37 = /follow_attacker_commands\.py/ nocase ascii wide
                        $string38 = /google_drive_doubledrive\.exe/ nocase ascii wide
                        $string39 = /google_drive_ransomware\.py/ nocase ascii wide
                        $string40 = /https\:\/\/api\.onedrive\.com\/v1\.0\/drives\/me\/items\/root\:\{onedrive_file_path\}\:\/oneDrive\.createUploadSession/ nocase ascii wide
                        $string41 = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=getDomainList/ nocase ascii wide
                        $string42 = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=getMessages\&login\=/ nocase ascii wide
                        $string43 = /https\:\/\/www\.1secmail\.com\/api\/v1\/\?action\=readMessage\&login\=/ nocase ascii wide
                        $string44 = /onedrive_doubledrive\.exe/ nocase ascii wide
                        $string45 = /onedrive_doubledrive\.py/ nocase ascii wide
                        $string46 = /onedrive_ransomware\.py/ nocase ascii wide
                        $string47 = /OneDriveRansomware\(CloudDriveRansomware\)/ nocase ascii wide
                        $string48 = "SafeBreach-Labs/DoubleDrive" nocase ascii wide
                        $string49 = "save the Fernet encryption/decryption key " nocase ascii wide
                        $string50 = "vssadmin delete shadows /all /quiet" nocase ascii wide

    condition:
        any of them
}