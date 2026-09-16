rule sha3_512_hashed_default_creds_super_micro_computer_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for super_micro_computer_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b12c327f742aac769cc3a8ebcb2dff2cb6bbf4ef7f8edd42ab65dbebb1cff8e72da7eef015355396474167708e54248fc8989a86b2da61c84f8fc5d500d2bd11"
    $a1="b12c327f742aac769cc3a8ebcb2dff2cb6bbf4ef7f8edd42ab65dbebb1cff8e72da7eef015355396474167708e54248fc8989a86b2da61c84f8fc5d500d2bd11"
condition:
    ($a0 and $a1)
}