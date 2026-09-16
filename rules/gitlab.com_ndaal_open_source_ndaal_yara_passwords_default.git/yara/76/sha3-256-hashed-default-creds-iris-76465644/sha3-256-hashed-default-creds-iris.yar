rule sha3_256_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="144b335042c98cdeffb44e61d31c20f2773d2a97455a6ba4183e426fb858b64a"
    $a1="fba5b62ca5ba0c65f1c393b8e35db139e5a6902695f8b52cdecb6c2db3de0811"
condition:
    ($a0 and $a1)
}