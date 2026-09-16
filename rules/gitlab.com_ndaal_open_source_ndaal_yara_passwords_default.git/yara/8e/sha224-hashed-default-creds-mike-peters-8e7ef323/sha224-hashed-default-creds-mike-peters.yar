rule sha224_hashed_default_creds_mike_peters
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcb80a936deca9704d30462d2ceb96e56af8d9a00cf7863bdfa91558"
    $a1="3e62cb8e84184f8179fd31cb560077376b5c44e88fcd311b20c1c8cc"
condition:
    ($a0 and $a1)
}