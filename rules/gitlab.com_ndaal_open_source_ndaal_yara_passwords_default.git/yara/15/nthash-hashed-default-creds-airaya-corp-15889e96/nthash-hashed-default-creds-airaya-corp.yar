rule nthash_hashed_default_creds_airaya_corp
{
    meta:
        id = "4w0CbTo6yQbD5snTxm7NGd"
        fingerprint = "19a16b268108899cdcb6eaf2278bb9fd3d3c32aed870945de3d10463d0de215b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for airaya_corp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a14314a36d29c44caaf2b13be175ac5"
    $a1="4a14314a36d29c44caaf2b13be175ac5"
condition:
    ($a0 and $a1)
}