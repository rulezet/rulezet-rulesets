rule nthash_hashed_default_creds_elasticsearch_web
{
    meta:
        id = "5KU79op0V4hcDixxlucy3c"
        fingerprint = "4ff437cce43e602f6b981b60569038850645b2be7901ad121d010e43d946f91c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for elasticsearch_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="5677c303b4f651753b51a512aa4b845a"
condition:
    ($a0 and $a1)
}