rule blake2b_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d456dbae707f166825ff591499ee1315367a3a56e596cfcba85ac1911870ad4c63b0731cf7dcb6c824854946f817da39516fc284787e7e46c3c9df781bd4812d"
    $a1="d456dbae707f166825ff591499ee1315367a3a56e596cfcba85ac1911870ad4c63b0731cf7dcb6c824854946f817da39516fc284787e7e46c3c9df781bd4812d"
condition:
    ($a0 and $a1)
}