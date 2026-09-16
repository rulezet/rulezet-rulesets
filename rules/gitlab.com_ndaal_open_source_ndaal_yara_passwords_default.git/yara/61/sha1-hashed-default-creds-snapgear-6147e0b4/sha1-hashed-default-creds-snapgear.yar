rule sha1_hashed_default_creds_snapgear
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for snapgear."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d26a862e80e9980f33f480dfda6ecd6bcb3ca806"
    $a1="0f1e327aa644cff77669b6995fd25cb15347ad21"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="7505d64a54e061b7acd54ccd58b49dc43500b635"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}