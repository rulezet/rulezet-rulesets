rule sha256_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="186f35856751d71617baad9dc7df6e7ab5d7d17348fdf473597da929977731e2"
    $a1="16d1b91e6218e62c6d0a5abae61abf83a55581c92e6d9da0087a21fcd615c3a6"
condition:
    ($a0 and $a1)
}