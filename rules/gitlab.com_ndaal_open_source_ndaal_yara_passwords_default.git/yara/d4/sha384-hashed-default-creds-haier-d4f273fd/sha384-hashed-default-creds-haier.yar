rule sha384_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b4b839c80b6d677ed9a0fb6b073d1a7f0568d12b996a71fc4988a0a5c388ad65ac81da1f82026991bbf3c833f355dac"
    $a1="730702cb5e06928726253b2c46e87d6c561e347fd9da67e981af3ecdc18497a02d5d2a618241a7bd815ae12326c66f24"
condition:
    ($a0 and $a1)
}