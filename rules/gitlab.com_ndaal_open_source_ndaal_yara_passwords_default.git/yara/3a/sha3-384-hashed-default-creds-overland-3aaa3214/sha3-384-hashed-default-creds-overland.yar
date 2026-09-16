rule sha3_384_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="420677fb158e8c3207566ddda5f7983239b89f99d2229fb03594b034cdc3d7f3a2253f202fe89931b7953bea6497ae5f"
    $a1="07bc09b5d98a45b3a068a1b342c86374b5a5be23a847e706ac5e7827e273fad1baff63eb5f68424efac7f596b5471f9a"
condition:
    ($a0 and $a1)
}