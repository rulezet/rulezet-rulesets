rule sha512_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b89e474591555e701dc58acd3cf38581209773612c50cebd01f5ab70922e29d100a4aa4bc4fc5751c5c55567bcfdd99b11f3b5d2015b10e7f7e965b703a0538a"
    $a1="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a2="33a807f905cd966d514a0af6aa6f06d7e2bd06ef459b740c57a04b23c40ed73ef914591afcb2e556989469a8666446bb222261086b67a2c9987f3a290298e26c"
    $a3="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a4="b4f8eef4b1240faee9fec6353acfbf54433d3e3ca53bac56fa7048cb02ab13db2a39a4886c90996dc451d195b0626e614001443506ea10611c60efb5cc814d1b"
    $a5="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}