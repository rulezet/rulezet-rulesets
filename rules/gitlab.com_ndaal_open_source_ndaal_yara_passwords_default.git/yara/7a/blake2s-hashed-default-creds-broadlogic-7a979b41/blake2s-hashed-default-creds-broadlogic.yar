rule blake2s_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
    $a1="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
    $a5="293eea3b1d83925a4c5794c9d2a7a049b796ba4831e66bbfff5ea318a264cb3f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}