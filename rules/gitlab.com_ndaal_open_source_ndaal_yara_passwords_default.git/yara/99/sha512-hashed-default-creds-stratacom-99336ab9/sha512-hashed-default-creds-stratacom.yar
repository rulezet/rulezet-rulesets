rule sha512_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d33938cbd0dac04f6e8e64917eaab5ef17c690939b0361447c5f70b8d2c8970e382104cc071452f3d00f7832a655aa5179a788fad06851cb5d4dd0e99da0c54f"
    $a1="353fef828b97f476d722500f1ea85dcf46107f789145b3854ce5c7a9a341da1d2c7a3d50095888d9d93f4caa075ee198a3a9d72353d5748dfadeb2b838c77809"
condition:
    ($a0 and $a1)
}