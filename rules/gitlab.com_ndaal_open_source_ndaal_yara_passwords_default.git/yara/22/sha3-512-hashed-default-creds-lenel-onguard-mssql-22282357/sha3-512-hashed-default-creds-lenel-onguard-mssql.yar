rule sha3_512_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d376e80144053d1bf3fb9e9707a606c52cacd6633b9d27a124d50e0e7703427b4dbb5fbca7bdceb1a84bbcab769f17967ea0e1c7b68227003058a0e94d77698d"
    $a1="d2ec02fdad226ad835db9c2d6c6bff10f5918bedc5260f0cdb2f75cd8c11ddeacc7faaa256e478a728474f53273077d9e4f2afdae7624415d21e1e3911929c69"
condition:
    ($a0 and $a1)
}