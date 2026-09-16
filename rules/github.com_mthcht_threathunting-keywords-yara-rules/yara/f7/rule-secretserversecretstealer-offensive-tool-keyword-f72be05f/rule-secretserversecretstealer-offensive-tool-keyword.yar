rule rule_SecretServerSecretStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SecretServerSecretStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecretServerSecretStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SecretServerSecretStealer_offensive_tool_keyword = " Local:DPAPIDecrypt" nocase ascii wide
                        $string2_SecretServerSecretStealer_offensive_tool_keyword = " Local:LoadEncryptionDll" nocase ascii wide
                        $string3_SecretServerSecretStealer_offensive_tool_keyword = /\sSecretStealer\.ps1/ nocase ascii wide
                        $string4_SecretServerSecretStealer_offensive_tool_keyword = /\s\-WebRoot\sC\:\\inetpub\\wwwroot\\SecretServer/ nocase ascii wide
                        $string5_SecretServerSecretStealer_offensive_tool_keyword = /\/SecretServerSecretStealer\.git/ nocase ascii wide
                        $string6_SecretServerSecretStealer_offensive_tool_keyword = /\/SecretServerSecretStealer\-master\.zip/ nocase ascii wide
                        $string7_SecretServerSecretStealer_offensive_tool_keyword = /\/SecretStealer\.ps1/ nocase ascii wide
                        $string8_SecretServerSecretStealer_offensive_tool_keyword = /\/thycotic_secretserver_dump\.rb/ nocase ascii wide
                        $string9_SecretServerSecretStealer_offensive_tool_keyword = /\\SecretStealer\.ps1/ nocase ascii wide
                        $string10_SecretServerSecretStealer_offensive_tool_keyword = /\\Thycotic\.ihawu\.EncryptionProtection_x64\.dll/ nocase ascii wide
                        $string11_SecretServerSecretStealer_offensive_tool_keyword = /\\Thycotic\.ihawu\.EncryptionProtection_x86\.dll/ nocase ascii wide
                        $string12_SecretServerSecretStealer_offensive_tool_keyword = /\\thycotic_secretserver_dump\.rb/ nocase ascii wide
                        $string13_SecretServerSecretStealer_offensive_tool_keyword = "a36e3489d4317d70fd2cb100020b0c53d575988b790ec33c4c4d204e5e834016" nocase ascii wide
                        $string14_SecretServerSecretStealer_offensive_tool_keyword = /aes.{0,1000}83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088/ nocase ascii wide
                        $string15_SecretServerSecretStealer_offensive_tool_keyword = "denandz/SecretServerSecretStealer" nocase ascii wide
                        $string16_SecretServerSecretStealer_offensive_tool_keyword = /Encryption\.config\svalues\sare\sencrypted\swith\sDPAPI\,\sdecrypting/ nocase ascii wide
                        $string17_SecretServerSecretStealer_offensive_tool_keyword = "Invoke-SecretDecrypt" nocase ascii wide
                        $string18_SecretServerSecretStealer_offensive_tool_keyword = "Invoke-SecretStealer" nocase ascii wide
                        $string19_SecretServerSecretStealer_offensive_tool_keyword = /xor.{0,1000}8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e/ nocase ascii wide

    condition:
        any of them
}