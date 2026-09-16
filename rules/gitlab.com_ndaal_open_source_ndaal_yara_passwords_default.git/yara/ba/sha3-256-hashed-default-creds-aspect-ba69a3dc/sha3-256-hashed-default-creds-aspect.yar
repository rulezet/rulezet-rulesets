rule sha3_256_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="313befa3dd5d8b2606045245fe48492706bbe14c7a4b846305f242e6c6d59e3c"
    $a1="e65f6a6be44d4eeed68fec04b7d9be433afc1fd0591e42a280f520b177f9532c"
condition:
    ($a0 and $a1)
}