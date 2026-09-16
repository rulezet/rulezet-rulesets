rule nthash_hashed_default_creds_openwave
{
    meta:
        id = "6BHWu2MU0YYNuVtO8MjVry"
        fingerprint = "737e3efd611bacb23eeb0141a09a9dc44d957d395043e1088340c60c7bdaf3fe"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="037f28c9c5b655a259c3aef6a232e724"
    $a1="782faf97b90472aa4997fce8abff4ab3"
    $a2="1c074f36a02bcb4fb1b6e0d24a0283cd"
    $a3="4fd0ab5b46db3d4bae053b78d3345800"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}