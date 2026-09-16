rule nthash_hashed_default_creds_autodesk
{
    meta:
        id = "49QYdIIchrkqJMMFi44lev"
        fingerprint = "a17f2a6e16a8dffbdbe877db5692f0c996264d8937de3a56ff32764f881a0e40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb0a7a182f6ad89b67ee47fbdb65a2cc"
    $a1="eb0a7a182f6ad89b67ee47fbdb65a2cc"
condition:
    ($a0 and $a1)
}