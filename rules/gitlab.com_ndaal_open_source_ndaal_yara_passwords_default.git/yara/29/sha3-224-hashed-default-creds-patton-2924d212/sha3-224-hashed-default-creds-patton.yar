rule sha3_224_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a1="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a2="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
    $a3="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}