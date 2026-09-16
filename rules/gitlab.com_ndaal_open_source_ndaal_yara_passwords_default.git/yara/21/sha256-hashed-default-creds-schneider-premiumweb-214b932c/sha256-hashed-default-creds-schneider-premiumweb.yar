rule sha256_hashed_default_creds_schneider_premiumweb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_premiumweb."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
    $a1="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
condition:
    ($a0 and $a1)
}