rule sha512_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a1742fef019f9d520ce8eeb17d9eecb14735cf0e44518e2b8cc828760e8b8987139dcdb62783530ad4bee70057645539a6d7f366b123ebfd97c57f5f57cb24d"
    $a1="1a1742fef019f9d520ce8eeb17d9eecb14735cf0e44518e2b8cc828760e8b8987139dcdb62783530ad4bee70057645539a6d7f366b123ebfd97c57f5f57cb24d"
condition:
    ($a0 and $a1)
}