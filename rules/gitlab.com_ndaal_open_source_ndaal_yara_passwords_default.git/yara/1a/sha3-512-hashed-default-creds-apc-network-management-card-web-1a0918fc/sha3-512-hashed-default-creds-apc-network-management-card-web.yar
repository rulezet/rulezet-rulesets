rule sha3_512_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a1="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a2="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a3="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
    $a4="cbbd1f5fc237b828503166e428a8fdf694033dfe1d56facc2d0e40c15cf484be8992c3356f6c274a0a9c291fb48344d6e1c1a22c4e574213e9ec79aceeb99105"
    $a5="a042b8def54466d33a9fa2de436041aac98bb190a245f7829b0f1ee858568e115ebb963491f5aabbec1e69d7deee0bdcf846bc626029b59ad517f520aa6a8f21"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}