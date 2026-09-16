rule blake2s_hashed_default_creds_ricoh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ricoh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="0eac0ddb08d482a2cb9e297e499508a9e4f4b229229d43a6f2f78d129ebfb203"
    $a4="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a5="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}