rule Chrome_App_Bound_Encryption_Decryption
{
    meta:
        description = "Detection patterns for the tool 'Chrome-App-Bound-Encryption-Decryption' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Chrome-App-Bound-Encryption-Decryption"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " App-Bound Encryption Decryption process" nocase ascii wide
                        $string2 = /\schrome_decrypt\.cpp\s/ nocase ascii wide
                        $string3 = /\schrome_decrypt\.cpp/ nocase ascii wide
                        $string4 = /\schrome_decrypt\.exe/ nocase ascii wide
                        $string5 = /\/chrome_decrypt\.exe/ nocase ascii wide
                        $string6 = /\/Chrome\-App\-Bound\-Encryption\-Decryption\.git/ nocase ascii wide
                        $string7 = /\[\+\]\sProxy\sblanket\sset\ssuccessfully/ nocase ascii wide
                        $string8 = /\\chrome_decrypt\.cpp/ nocase ascii wide
                        $string9 = /\\chrome_decrypt\.exe/ nocase ascii wide
                        $string10 = "350cfd6e53c72d9c3d2fa109cc73e69171d8f1bed85ced979483592908925aff" nocase ascii wide
                        $string11 = /Alexander\sHagenah\s\(\@xaitax\)/ nocase ascii wide
                        $string12 = "'app_bound_encrypted_key' not found in Local State file" nocase ascii wide
                        $string13 = "b41498d3c4883fb374dce5c9923c60b5ac901775909ae74d13a05851b80cc221" nocase ascii wide
                        $string14 = "Chrome App-Bound Encryption - Decryption" nocase ascii wide
                        $string15 = /ChromeAppBound\:\:BytesToHexString\(en\scrypted_key\.data/ nocase ascii wide
                        $string16 = /MIDL_INTERFACE\(\\"A949CB4E\-C4F9\-44C4\-B213\-6BF8AA9AC69C\\"\)/ nocase ascii wide
                        $string17 = "xaitax/Chrome-App-Bound-Encryption-Decryption" nocase ascii wide
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