rule sha224_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1442566f5c53734e4dbe4de30560a9ad7f64b1e3f241821f643b4262"
    $a1="1442566f5c53734e4dbe4de30560a9ad7f64b1e3f241821f643b4262"
condition:
    ($a0 and $a1)
}