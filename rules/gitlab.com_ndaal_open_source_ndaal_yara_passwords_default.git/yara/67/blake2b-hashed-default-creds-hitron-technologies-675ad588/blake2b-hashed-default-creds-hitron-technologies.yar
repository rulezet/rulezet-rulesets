rule blake2b_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="144d7a1c2fbc087c3cd57c50e2bb165a016f3d50d67d53dd2a07c8d451325730992d3f638d392651fc4a1e5f96ecc415a27ecab7915b6da8fe9493007489da47"
    $a3="6037200f00e97af99a676d084485c02b77ff937fd96626d8eebedfd4391f57829294a2a997c3053bd27ec9470fe6c19d8d80846817dbec773174b3bd61a51181"
    $a4="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a5="4821d6006e6c5f0f1243f7902de4755604f519f7f623f16df1453cbf451bc57ab06e832a494cd5a4e3fc9a228b1cf3f1db63afb97b26468424baa268ce0fafd0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}