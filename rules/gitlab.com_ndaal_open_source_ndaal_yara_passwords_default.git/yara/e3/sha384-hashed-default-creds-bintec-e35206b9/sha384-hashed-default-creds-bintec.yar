rule sha384_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21bcd754b7a0edf18d107852857a59ec252e1f99e9a8d35c7bccf81f295ca085fe1b140509439df467ef5917cc7d17fd"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="c4e11f026a6e689252a809110c8356add5b25642230d49f3c00a7f5dc58f26bfccfd40ecd227e834c0416045a73d6f2d"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="4c88a9f3e84234bbed809d07d3bcfd9a053607b261ffdfce2dfb45b703430c28beae1470a1f35855e20b5a5ff394f220"
    $a5="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}