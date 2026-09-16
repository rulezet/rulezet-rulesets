rule sha384_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c4833f76f4f6d777618974dd06ea9afcb903b9a5babab74de3a9bb841dede4b493f8b8144f68cd10d702f57682709fb"
    $a1="5760f1c638d78b33bd719ce3c50895706db638cd9f98201b0682cc0ef862424576c6eed870613dad65a3e388d222d816"
condition:
    ($a0 and $a1)
}