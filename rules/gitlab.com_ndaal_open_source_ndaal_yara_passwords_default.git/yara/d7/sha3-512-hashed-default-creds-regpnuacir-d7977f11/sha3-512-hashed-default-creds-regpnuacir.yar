rule sha3_512_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8059160be47a1cf875f097587f340c5c3a91821d78bd2fcce01583313e37806f48f7f47e428a43d0dafdaff454b7d208439a28dae530bcba9c3d9004d61948f6"
    $a1="08271866e8bf85bb557857824e1a7c837aa3aaa85271337679b629e821ab8139b1d451a8ca904c06dde295741a309634c8a90b456bb1687e2c8c20eb79f2c567"
condition:
    ($a0 and $a1)
}