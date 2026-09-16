rule rule_ShellSync_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShellSync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellSync"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShellSync_offensive_tool_keyword = /\sb64\.ps1\s/ nocase ascii wide
                        $string2_ShellSync_offensive_tool_keyword = /\scheckRoot\.ps1/ nocase ascii wide
                        $string3_ShellSync_offensive_tool_keyword = /\spngZIP\.ps1/ nocase ascii wide
                        $string4_ShellSync_offensive_tool_keyword = /\/checkRoot\.ps1/
                        $string5_ShellSync_offensive_tool_keyword = /\/pngZIP\.ps1/
                        $string6_ShellSync_offensive_tool_keyword = /\/ShellSync\.git/ nocase ascii wide
                        $string7_ShellSync_offensive_tool_keyword = /\/ShellSync\-main\.zip/ nocase ascii wide
                        $string8_ShellSync_offensive_tool_keyword = /\\b64\.ps1/ nocase ascii wide
                        $string9_ShellSync_offensive_tool_keyword = /\\checkRoot\.ps1/ nocase ascii wide
                        $string10_ShellSync_offensive_tool_keyword = /\\fileUpload\.ps1/ nocase ascii wide
                        $string11_ShellSync_offensive_tool_keyword = /\\pngZIP\.ps1/ nocase ascii wide
                        $string12_ShellSync_offensive_tool_keyword = /\\ShellSync\-main\.zip/ nocase ascii wide
                        $string13_ShellSync_offensive_tool_keyword = "0699ec05b54bc85473e88e53a615a630ca97c68bc8a96e126c1168245b0a74b6" nocase ascii wide
                        $string14_ShellSync_offensive_tool_keyword = "171b5c5e7631493dd1959913d21a9f94d75079507fa321f5fa61d37df07866b9" nocase ascii wide
                        $string15_ShellSync_offensive_tool_keyword = "5c3a2b52076490d4dbcff0a880931e52fe492e253e003961bae52c99e23d25b0" nocase ascii wide
                        $string16_ShellSync_offensive_tool_keyword = "75e1281a581e12bdec70ffa44dbe469847590eab3deddedfe2e6be0b91cf88c2" nocase ascii wide
                        $string17_ShellSync_offensive_tool_keyword = "784adbcf1820556ae22793a98e8bc802017598d4ee00a63c2c5a735b744009f6" nocase ascii wide
                        $string18_ShellSync_offensive_tool_keyword = "7a9171a7fe5be4b0676faad4c3f65124e0e2a73b79ec5b219da2204a64a3f3c7" nocase ascii wide
                        $string19_ShellSync_offensive_tool_keyword = "85a64d925bmsh374c814867fca19p1c3880jsn5cff8c77bdb3" nocase ascii wide
                        $string20_ShellSync_offensive_tool_keyword = "86b62609337b5c5c46a2f007f4b5126679728016c0095938646365d495c80a39" nocase ascii wide
                        $string21_ShellSync_offensive_tool_keyword = "8f78ba859a0d8f7a131310f48406af6faf0496871588ffb071bd186cdc8e8e65" nocase ascii wide
                        $string22_ShellSync_offensive_tool_keyword = "9f1af0a9b870f562131c2dbb25a3fe416512b0d74b7e57a0f2dcc4b7039383bd" nocase ascii wide
                        $string23_ShellSync_offensive_tool_keyword = "Add-PodeEndpoint -Address localhost -Port " nocase ascii wide
                        $string24_ShellSync_offensive_tool_keyword = "d5f0032f2d09939afd7f054530076eefe4cdaca9a625197d12f3f13a92e884d0" nocase ascii wide
                        $string25_ShellSync_offensive_tool_keyword = "eae10507ae68eb619503bf0ea16b0d7fd4a1eb5d817bde2746413fb27c1e5aa5" nocase ascii wide
                        $string26_ShellSync_offensive_tool_keyword = /https\:\/\/api\.fbi\.gov\/wanted\/v1\/list/ nocase ascii wide
                        $string27_ShellSync_offensive_tool_keyword = /https\:\/\/privatix\-temp\-mail\-v1\.p\.rapidapi\.com\/request\/domains\// nocase ascii wide
                        $string28_ShellSync_offensive_tool_keyword = /https\:\/\/privatix\-temp\-mail\-v1\.p\.rapidapi\.com\/request\/mail\/id\/null\// nocase ascii wide
                        $string29_ShellSync_offensive_tool_keyword = "I-Am-Jakoby/ShellSync" nocase ascii wide
                        $string30_ShellSync_offensive_tool_keyword = /jakoby\.lol\/fbi/ nocase ascii wide
                        $string31_ShellSync_offensive_tool_keyword = "Monitor-FBIWantedList -searchName " nocase ascii wide
                        $string32_ShellSync_offensive_tool_keyword = "New-PodeWebNavDropdown -Name " nocase ascii wide
                        $string33_ShellSync_offensive_tool_keyword = "Set-PodeWebSocial -Type " nocase ascii wide

    condition:
        any of them
}