rule sha1_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80437a44a661d141174209119d54125a59a64b2a"
    $a1="80437a44a661d141174209119d54125a59a64b2a"
    $a2="d186e8dac48a24d0115b568d0ab2c9e8b82e6adb"
    $a3="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
    $a4="c6fcd99559b7b8626f622074178541e4cd4f6cd0"
    $a5="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}