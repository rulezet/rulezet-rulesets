rule blake2s_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48be87a5445f158975f2ef6fac329ca333eabe0f1afcdc327ab1a6c4ae417e9e"
    $a1="ae97729b645f81a275ed811ed8b4f6c5e646c70b17d2b5f1f24c34cd80a7465e"
    $a2="9fa465cfeca39e1e0ffd65d6e7bd4a5aed840a48c96127d05f7072623ad1a0e8"
    $a3="899874a085ecf026a11adafdeb61ec1db9dfefe1a8cf460f10fe3762702624f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}