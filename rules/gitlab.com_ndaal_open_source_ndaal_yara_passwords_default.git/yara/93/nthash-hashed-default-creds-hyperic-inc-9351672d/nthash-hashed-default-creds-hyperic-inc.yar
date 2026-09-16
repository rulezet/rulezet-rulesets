rule nthash_hashed_default_creds_hyperic_inc
{
    meta:
        id = "7FpEVpzbsOzrqp2aZXSqNm"
        fingerprint = "2daf6d5edb7e77aeea5d981cd9fa7284625260ce7ec925affa9fbf4a217e289e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99ca17566ebc7718cad9218634601526"
    $a1="99ca17566ebc7718cad9218634601526"
condition:
    ($a0 and $a1)
}