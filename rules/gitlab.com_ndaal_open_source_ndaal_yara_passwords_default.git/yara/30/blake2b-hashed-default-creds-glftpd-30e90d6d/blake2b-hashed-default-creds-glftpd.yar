rule blake2b_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="045237964ab8999e285a4a2fb4c64a5cc4835805245d68643378c0e4f6076404bd582c2d17b03e6cd5eb22bc562c9203d0d46794cf995a6877a67676e70680e5"
    $a1="045237964ab8999e285a4a2fb4c64a5cc4835805245d68643378c0e4f6076404bd582c2d17b03e6cd5eb22bc562c9203d0d46794cf995a6877a67676e70680e5"
condition:
    ($a0 and $a1)
}