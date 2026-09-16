rule sha3_512_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81381e2fa9bfe4eb3ed7c90e73a52dfb39437c3d7ecca0c7e01bff54e7d4d4247c0a1cbbcf505ad2819893e831a813b2f0571a33349bfaef310450d7f3b8dca2"
    $a1="81381e2fa9bfe4eb3ed7c90e73a52dfb39437c3d7ecca0c7e01bff54e7d4d4247c0a1cbbcf505ad2819893e831a813b2f0571a33349bfaef310450d7f3b8dca2"
condition:
    ($a0 and $a1)
}