rule sha1_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fda4483e0d2d6e93aa2a40e01739323051bab4b"
    $a1="25c5d184fd3c8e7d24af0e237c061f5480a5e86e"
    $a2="1fda4483e0d2d6e93aa2a40e01739323051bab4b"
    $a3="1fda4483e0d2d6e93aa2a40e01739323051bab4b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}