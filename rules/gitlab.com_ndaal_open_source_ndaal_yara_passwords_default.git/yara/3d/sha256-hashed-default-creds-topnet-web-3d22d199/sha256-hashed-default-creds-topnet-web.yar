rule sha256_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99351f88dd917f353be0e11ad19409d647c30c6b3cc2d4075e2127e011b4a3b0"
    $a1="99351f88dd917f353be0e11ad19409d647c30c6b3cc2d4075e2127e011b4a3b0"
condition:
    ($a0 and $a1)
}