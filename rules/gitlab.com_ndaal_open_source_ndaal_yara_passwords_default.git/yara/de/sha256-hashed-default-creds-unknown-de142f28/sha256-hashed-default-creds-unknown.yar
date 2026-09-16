rule sha256_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e117fc61b613553c380b34b0ed4f7afe087008fab3d56bb7d08b825353a55d5c"
    $a1="e117fc61b613553c380b34b0ed4f7afe087008fab3d56bb7d08b825353a55d5c"
    $a2="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a3="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
    $a4="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    $a5="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}