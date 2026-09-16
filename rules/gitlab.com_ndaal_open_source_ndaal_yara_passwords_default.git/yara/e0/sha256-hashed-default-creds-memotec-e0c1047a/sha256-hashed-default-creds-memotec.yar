rule sha256_hashed_default_creds_memotec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for memotec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0834c2d60725ac5902257b3b78dd161ad26d1c0290dbf1e47cc14add5b8c8142"
    $a1="c2dd62dc3c825209b1a778fcbc258109a5c21d87d4dcf43955bb6839cc82be1b"
condition:
    ($a0 and $a1)
}