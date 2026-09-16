rule sha512_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fcfd7c8a306a34d388c4d6436224221738902ae7021fab7c597be77d4b51ce0455901b288c75b7fb916e83c59d11d82bc8a833a9577e17cd85c22d27b446d666"
    $a1="162086dbf1fc8beee5e8f625279a9620d782c1f6d16e1fba27ac01a02703e5f4588116c866f94f7ee07cc72740b8a32c1822695a0614ec9ed3a75ee586195cab"
condition:
    ($a0 and $a1)
}