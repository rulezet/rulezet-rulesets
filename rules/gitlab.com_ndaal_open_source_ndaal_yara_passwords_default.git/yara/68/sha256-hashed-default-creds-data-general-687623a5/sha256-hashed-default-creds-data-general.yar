rule sha256_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a1="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a2="037aeaeaf4bbf26ddabe7256a8294dc52da48d575a1247b5c2598c47de7aebab"
    $a3="037aeaeaf4bbf26ddabe7256a8294dc52da48d575a1247b5c2598c47de7aebab"
    $a4="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a5="037aeaeaf4bbf26ddabe7256a8294dc52da48d575a1247b5c2598c47de7aebab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}