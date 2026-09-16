rule sha224_hashed_default_creds_cyclades
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyclades."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ed486c8dab8e3a264e3a3ccbdbfab07d1099b047fc870196956a265"
    $a1="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
    $a2="73bd383488d5d71611a24d2e27ee0106f105ec54cad483a712cdd4d6"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}