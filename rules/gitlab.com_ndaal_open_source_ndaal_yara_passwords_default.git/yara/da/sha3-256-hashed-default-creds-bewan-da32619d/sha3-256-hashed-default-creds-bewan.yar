rule sha3_256_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76544ae8db0e95efc605e8f44d4b0fc0e10662ec9516b897b7a513e3c1e7dbb5"
    $a1="76544ae8db0e95efc605e8f44d4b0fc0e10662ec9516b897b7a513e3c1e7dbb5"
condition:
    ($a0 and $a1)
}