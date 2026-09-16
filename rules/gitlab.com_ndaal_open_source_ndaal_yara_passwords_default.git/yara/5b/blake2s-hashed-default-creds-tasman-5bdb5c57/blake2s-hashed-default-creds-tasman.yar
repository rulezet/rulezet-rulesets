rule blake2s_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e3b2de5947a6cde05dd63697d585cae20eef5cbba476da7370ceb7983e46befc"
    $a1="b2f150f3f7b086b0f9359658435fc8efb97dd7d7a4d451a6492a4362ea50fe2f"
condition:
    ($a0 and $a1)
}