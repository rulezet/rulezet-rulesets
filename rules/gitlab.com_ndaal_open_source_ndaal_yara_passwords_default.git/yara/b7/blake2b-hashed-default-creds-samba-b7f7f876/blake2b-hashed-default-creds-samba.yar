rule blake2b_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfdac9ce1773da6d763d9a76e0d4e74b0f284e9df7f1a04d9145d04ac1117fee14b6a54e1574c7834604e3b60b122f4674e5f0d1535740a0b612b60abd67e7cf"
    $a1="bfdac9ce1773da6d763d9a76e0d4e74b0f284e9df7f1a04d9145d04ac1117fee14b6a54e1574c7834604e3b60b122f4674e5f0d1535740a0b612b60abd67e7cf"
condition:
    ($a0 and $a1)
}