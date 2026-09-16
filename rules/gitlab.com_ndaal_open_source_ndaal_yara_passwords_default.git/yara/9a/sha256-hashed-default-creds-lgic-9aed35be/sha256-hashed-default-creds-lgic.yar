rule sha256_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c9fcc48e1ad8f060ac2d5cccf61a40ac77cad046e80fd6f1e629a394409cacc"
    $a1="9c9fcc48e1ad8f060ac2d5cccf61a40ac77cad046e80fd6f1e629a394409cacc"
condition:
    ($a0 and $a1)
}