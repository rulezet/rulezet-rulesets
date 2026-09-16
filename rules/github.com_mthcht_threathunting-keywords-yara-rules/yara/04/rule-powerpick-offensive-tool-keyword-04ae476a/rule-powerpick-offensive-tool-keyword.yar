rule rule_Powerpick_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Powerpick' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powerpick"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Powerpick_offensive_tool_keyword = /\/DLLEnc\.ps1/ nocase ascii wide
                        $string2_Powerpick_offensive_tool_keyword = /\/PowerPick\.exe/ nocase ascii wide
                        $string3_Powerpick_offensive_tool_keyword = /\/PSInject\.ps1/ nocase ascii wide
                        $string4_Powerpick_offensive_tool_keyword = /\/ReflectivePick_x64\.dll/ nocase ascii wide
                        $string5_Powerpick_offensive_tool_keyword = /\/ReflectivePick_x86\.dll/ nocase ascii wide
                        $string6_Powerpick_offensive_tool_keyword = /\/sharppick\.exe/ nocase ascii wide
                        $string7_Powerpick_offensive_tool_keyword = /\\DLLEnc\.ps1/ nocase ascii wide
                        $string8_Powerpick_offensive_tool_keyword = /\\PowerPick\.exe/ nocase ascii wide
                        $string9_Powerpick_offensive_tool_keyword = /\\PowerPick\\SharpPick\\/ nocase ascii wide
                        $string10_Powerpick_offensive_tool_keyword = /\\PowerTools\\PowerPick\\/ nocase ascii wide
                        $string11_Powerpick_offensive_tool_keyword = /\\PSInject\.ps1/ nocase ascii wide
                        $string12_Powerpick_offensive_tool_keyword = /\\ReflectivePick\.cpp/ nocase ascii wide
                        $string13_Powerpick_offensive_tool_keyword = /\\ReflectivePick_x64\.dll/ nocase ascii wide
                        $string14_Powerpick_offensive_tool_keyword = /\\ReflectivePick_x86\.dll/ nocase ascii wide
                        $string15_Powerpick_offensive_tool_keyword = /\\sharppick\.exe/ nocase ascii wide
                        $string16_Powerpick_offensive_tool_keyword = "_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H" nocase ascii wide
                        $string17_Powerpick_offensive_tool_keyword = "5ED2F78E-8538-4C87-BCED-E19E9DAD879C" nocase ascii wide
                        $string18_Powerpick_offensive_tool_keyword = "780d27ade8e534dc6affd96eeeea3e5ca9bf3e8fc3cc3257597b90f855dd583c" nocase ascii wide
                        $string19_Powerpick_offensive_tool_keyword = "7C3D26E5-0A61-479A-AFAC-D34F2659F301" nocase ascii wide
                        $string20_Powerpick_offensive_tool_keyword = "AAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gR" nocase ascii wide
                        $string21_Powerpick_offensive_tool_keyword = /AAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAC4Fx3y\/HZzofx2c6H8dnOh4iTgof52c6GTANih\+XZzoefr7aHvdnOh9Q7gofl2c6H8dnKhoHZzoefr2aGVdnO/ nocase ascii wide
                        $string22_Powerpick_offensive_tool_keyword = /AAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACp8yO07ZJN5\+2STeftkk3n88De5\+\+STeeC5Obn6JJN5\/YP5ufFkk3n9g\/n54ySTef2D9Pn55JN5\+Tq3ufokk3/ nocase ascii wide
                        $string23_Powerpick_offensive_tool_keyword = "afed646dee07893f5be9103606c2eeda2545e75b59b03e0a1e2fc42940e09d43" nocase ascii wide
                        $string24_Powerpick_offensive_tool_keyword = "c7895e40feadeded96faf3a9c5fb0423bc16c5005aa419771c70849e9679e807" nocase ascii wide
                        $string25_Powerpick_offensive_tool_keyword = /Console\.Write\(\\"InexorablePoSH/ nocase ascii wide
                        $string26_Powerpick_offensive_tool_keyword = /import\-module\spsinject\.ps1/ nocase ascii wide
                        $string27_Powerpick_offensive_tool_keyword = /inexorableposh\.exe/ nocase ascii wide
                        $string28_Powerpick_offensive_tool_keyword = "Invoke-PSInject" nocase ascii wide
                        $string29_Powerpick_offensive_tool_keyword = "powerpick Get-" nocase ascii wide
                        $string30_Powerpick_offensive_tool_keyword = "PowerShellRunner_dll_len" nocase ascii wide
                        $string31_Powerpick_offensive_tool_keyword = /sharppick\.exe\s/ nocase ascii wide

    condition:
        any of them
}