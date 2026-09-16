rule sha3_384_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a42d04a5b4a2ea45ecf45279aaf3ec8fd906355e3ab856231ae7815a5df6a96f76fe4987dd638981314c942ba825de69"
    $a1="a42d04a5b4a2ea45ecf45279aaf3ec8fd906355e3ab856231ae7815a5df6a96f76fe4987dd638981314c942ba825de69"
    $a2="db0c42ee60209d2a0a429e6d2ac6dd4bc4b87a9178ff8c7429b07c6a312616dceea72e711c85e3dea04d35117a1c83e6"
    $a3="db0c42ee60209d2a0a429e6d2ac6dd4bc4b87a9178ff8c7429b07c6a312616dceea72e711c85e3dea04d35117a1c83e6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}