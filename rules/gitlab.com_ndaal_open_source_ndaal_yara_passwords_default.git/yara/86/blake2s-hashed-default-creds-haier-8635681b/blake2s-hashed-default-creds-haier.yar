rule blake2s_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e962df329fc4dd7000e38a32a881b2d3bed695e1601fc16cbd3cb883fc4a7c68"
    $a1="c300306bdf9cfa241e7aff1d344bef6bba7f8dedf2693f6be4e0912484d440ab"
condition:
    ($a0 and $a1)
}