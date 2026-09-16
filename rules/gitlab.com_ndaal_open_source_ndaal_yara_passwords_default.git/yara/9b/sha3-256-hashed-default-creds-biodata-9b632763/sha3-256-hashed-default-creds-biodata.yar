rule sha3_256_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11458aa3f98d695bb3b1a69458847323cf5b764182fec35c00bac65ad524b705"
    $a1="1ea838694151cac8901271a9dd8fa6e5ce4202becae780bf4c04024d4f76695f"
condition:
    ($a0 and $a1)
}