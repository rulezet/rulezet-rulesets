rule sha384_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="772e92d491db143f1a7c9ef776e0684f7d1c7077450dac1a99215241bee5427d8f6d386f039cb5b47661fc92f2ca56aa"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="403c86809bf4deebb534120b3441278d16b3e44b2fd264a7caf1c66c19bc81c741c12eec349d49b1054afd0cd4a505bd"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="2845d2352e91ec6c23950ffae8d2068256bfa3328b8be6b0f05e64165a88badbe3d1bd046a131b6584d32e8196a2e73c"
    $a5="2845d2352e91ec6c23950ffae8d2068256bfa3328b8be6b0f05e64165a88badbe3d1bd046a131b6584d32e8196a2e73c"
    $a6="5d61c1cc3d79cd7f3667e544fdb52d28f0f612f21a371f7829b2eccede68abd33a4d3bd9d7830392c534626af31b88c4"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}