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

    condition:
        any of them
}