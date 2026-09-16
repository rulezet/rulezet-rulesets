rule SecretServerSecretStealer
{
    meta:
        description = "Detection patterns for the tool 'SecretServerSecretStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecretServerSecretStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Local:DPAPIDecrypt" nocase ascii wide
                        $string2 = " Local:LoadEncryptionDll" nocase ascii wide
                        $string3 = /\sSecretStealer\.ps1/ nocase ascii wide
                        $string4 = /\s\-WebRoot\sC\:\\inetpub\\wwwroot\\SecretServer/ nocase ascii wide
                        $string5 = /\/SecretServerSecretStealer\.git/ nocase ascii wide
                        $string6 = /\/SecretServerSecretStealer\-master\.zip/ nocase ascii wide
                        $string7 = /\/SecretStealer\.ps1/ nocase ascii wide
                        $string8 = /\/thycotic_secretserver_dump\.rb/ nocase ascii wide
                        $string9 = /\\SecretStealer\.ps1/ nocase ascii wide
                        $string10 = /\\Thycotic\.ihawu\.EncryptionProtection_x64\.dll/ nocase ascii wide
                        $string11 = /\\Thycotic\.ihawu\.EncryptionProtection_x86\.dll/ nocase ascii wide
                        $string12 = /\\thycotic_secretserver_dump\.rb/ nocase ascii wide
                        $string13 = "a36e3489d4317d70fd2cb100020b0c53d575988b790ec33c4c4d204e5e834016" nocase ascii wide
                        $string14 = /aes.{0,100}83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088/ nocase ascii wide
                        $string15 = "denandz/SecretServerSecretStealer" nocase ascii wide
                        $string16 = /Encryption\.config\svalues\sare\sencrypted\swith\sDPAPI\,\sdecrypting/ nocase ascii wide
                        $string17 = "Invoke-SecretDecrypt" nocase ascii wide
                        $string18 = "Invoke-SecretStealer" nocase ascii wide
                        $string19 = /xor.{0,100}8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}