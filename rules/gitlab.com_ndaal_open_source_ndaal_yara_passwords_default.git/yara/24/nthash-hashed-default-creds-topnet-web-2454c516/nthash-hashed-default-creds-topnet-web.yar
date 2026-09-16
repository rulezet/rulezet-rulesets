rule nthash_hashed_default_creds_topnet_web
{
    meta:
        id = "6SBVScniEhJbwu44DXWEIU"
        fingerprint = "9a95a5539c814ef10eb78bbd3b2f4230f1bcbe6f2144afc6dc5463ec16d42a61"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd2137d1c589e15dcfb5a6c3b974f00d"
    $a1="fd2137d1c589e15dcfb5a6c3b974f00d"
condition:
    ($a0 and $a1)
}