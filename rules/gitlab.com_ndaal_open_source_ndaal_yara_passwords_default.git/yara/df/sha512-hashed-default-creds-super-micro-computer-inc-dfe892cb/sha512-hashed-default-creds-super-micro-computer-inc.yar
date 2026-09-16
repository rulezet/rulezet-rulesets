rule sha512_hashed_default_creds_super_micro_computer_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for super_micro_computer_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="238b90e6e2382ddafadc35266b2fa9a371fb3962b675ccab1b5538321f469070d0f3762f29b21ac7ad772eb6bd299d09f8e75d38ed8b7067965d5d5f26ebc3f5"
    $a1="238b90e6e2382ddafadc35266b2fa9a371fb3962b675ccab1b5538321f469070d0f3762f29b21ac7ad772eb6bd299d09f8e75d38ed8b7067965d5d5f26ebc3f5"
condition:
    ($a0 and $a1)
}