rule sha1_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a60a1c7a9d688223d948e83e6a2cb40cd7c83f3b"
    $a1="a60a1c7a9d688223d948e83e6a2cb40cd7c83f3b"
    $a2="d44294dabb5559d834f8f8d1c5d4fd75c165770e"
    $a3="d44294dabb5559d834f8f8d1c5d4fd75c165770e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}