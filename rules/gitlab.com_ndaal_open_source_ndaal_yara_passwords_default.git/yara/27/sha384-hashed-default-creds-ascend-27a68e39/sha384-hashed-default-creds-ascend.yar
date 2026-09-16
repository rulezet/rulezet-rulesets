rule sha384_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d6c3fe9b85eb9028a901801247e8fe30983c3de24b0a0af9d64867b8ea05f208e7c9a0d22bfb60c142d834511b681017"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="3fe35e481a78c49434a85ead9d705ed62919749d5e766cd2d6ef060127181ca83cd4087b6e11644b2f09a3957fb78c7c"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="d12fdf2e3f04f870d878b475689c612b02e3214bbe9446904dd412a3d2e9801d0b1b1850f7307807d086dd100257092f"
    $a5="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
    $a6="f4d6fe6f62934bf34a452ce6184e42a4892a40a70371eb2e883c8573b93349afc606c710db090584dbe31ef4c22b1078"
    $a7="07118c8912d6527cd58200ac894bf3abf0aa38c27d0db9fb866e0016f348cf3b59b7a96e14e000217d01d00e0734c76c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}