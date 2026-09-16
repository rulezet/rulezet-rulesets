rule sha3_512_hashed_default_creds_apc_ups_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_ups_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a1="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
condition:
    ($a0 and $a1)
}