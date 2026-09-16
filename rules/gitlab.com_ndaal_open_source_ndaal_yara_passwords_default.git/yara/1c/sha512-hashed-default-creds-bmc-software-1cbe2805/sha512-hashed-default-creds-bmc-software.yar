rule sha512_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf6971a43cd56a6ef8a0a0be1bc3f0c98ad1a32cffcf9a6e741424cb214b94e239f58303df5a808949114993b41cabff5f30d75cf6e4dfa8970df40b34d73b40"
    $a1="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a2="28fecdbd0fe2a78f281159f5fc18ed7ba1c6786da6f2007842c27f39f6927066a45962a16dee7dc61532ec2a8bce55a2855d143c4fcb2503075e8ebe2407275f"
    $a3="a31b8f4074f0695d0f1df345fb854c1d149fe7043455f3e12ee00d2b3b2c31f849769f04f843edb52739ed070ead98eec6ae56cbe9cb611aba101742db21b61f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}