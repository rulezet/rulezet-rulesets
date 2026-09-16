rule sha3_224_hashed_default_creds_sprint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sprint."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a1="a6fbf7e5a4a4229434092bceca51f2313889138967e84f5ef1c01a9a"
condition:
    ($a0 and $a1)
}