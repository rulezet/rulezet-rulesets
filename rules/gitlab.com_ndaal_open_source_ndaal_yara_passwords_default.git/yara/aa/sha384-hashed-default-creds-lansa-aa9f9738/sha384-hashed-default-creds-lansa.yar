rule sha384_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="2e8b6d243879f5e69e065342a17d5d2f57c903bd35e940f7393323665b5a1d5e5e1e9449b154a8462e5ba9da8928889a"
    $a3="2e8b6d243879f5e69e065342a17d5d2f57c903bd35e940f7393323665b5a1d5e5e1e9449b154a8462e5ba9da8928889a"
    $a4="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a5="31938955b9fd154307247e26c787110737e9a84649d7366df2076ffe1fad09ad82864508693fdc092cfe7a6f6dcf6b53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}