rule sha3_384_hashed_default_creds_wang
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wang."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9263a17a02ff0c9f7554450e0e76eba297c2505e6000b4f0ad6bd3e0529b6b6d2e26abe582850dda273e7daa0f75a0ab"
    $a1="e5440a265cc83cbf9a98af9aac98d6a4610086c6110348886160aab958c1409265eb48fb93ac9ef2bf42d6d57e58b8cf"
condition:
    ($a0 and $a1)
}