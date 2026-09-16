rule sha3_224_hashed_default_creds_pikatel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pikatel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfbe665e81e732f9992cd71dedfef5784cb5ccfa419816bc930c812a"
    $a1="cfbe665e81e732f9992cd71dedfef5784cb5ccfa419816bc930c812a"
condition:
    ($a0 and $a1)
}