rule sha3_512_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
    $a1="2eccb593b748c043fecf5dcf9f9af9126b45c5f5eca95d7ee3d223585ab4f3628b1753ea168df21376f6e5dd9af0cf0b1b48ee78367d01589d5ca1019a1356c5"
condition:
    ($a0 and $a1)
}