rule nthash_hashed_default_creds_huawei
{
    meta:
        id = "f5dN3hkRDXwGvRzzbsHtB"
        fingerprint = "ab3be9e451258f2a787acbdf95e10e06a985ff3f7852ed381f552a2fb0bd0c54"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="30994df9e2969f59cf3ea1ab3284fa6a"
    $a2="79c6899ea65d358ede499b529712a650"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="0d729832a1e9143086308e70cbc8037d"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="4b0b41a2380a3a8d77e548a0256eae35"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="2f86c1a2ce778c4f5c97938e392e043f"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}