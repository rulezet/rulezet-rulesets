rule sha256_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="166cfb0e8bff35f92abb8a9a90df45610ac02af4990d740adae6cb00bc16e2f9"
    $a1="166cfb0e8bff35f92abb8a9a90df45610ac02af4990d740adae6cb00bc16e2f9"
condition:
    ($a0 and $a1)
}