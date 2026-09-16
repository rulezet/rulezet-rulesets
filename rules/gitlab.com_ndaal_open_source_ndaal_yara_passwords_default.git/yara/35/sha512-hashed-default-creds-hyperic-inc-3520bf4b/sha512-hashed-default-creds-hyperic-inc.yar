rule sha512_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e4820193be3c13daa7156cca78bd33de6ef6d05111bd3b3a712adcc7bd4004bfb54c7e8820c8578c4db457ec6684eb529474df547cec0f8afc8e77a13b8f8ee7"
    $a1="e4820193be3c13daa7156cca78bd33de6ef6d05111bd3b3a712adcc7bd4004bfb54c7e8820c8578c4db457ec6684eb529474df547cec0f8afc8e77a13b8f8ee7"
condition:
    ($a0 and $a1)
}