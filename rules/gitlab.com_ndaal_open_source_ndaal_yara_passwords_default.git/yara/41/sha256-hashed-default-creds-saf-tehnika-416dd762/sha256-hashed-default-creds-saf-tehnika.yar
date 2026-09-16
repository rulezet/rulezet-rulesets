rule sha256_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="389e10a474636c2abdd57563c280e18ed45d3c945efe3b43496b209a7c0cc2e6"
    $a1="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a2="41be026a4d4176681f15565f9f9f7bf8d41bd187795fedd8535f36630ff39aed"
    $a3="168196d133817ed25c3fe0bf9a5254309ab899daa622e81d3ead0daf0eb33def"
    $a4="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a5="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a6="2ff21e440ac5f885fe8a43b80bf2fdf88af461730ce3afef950f8efa840af993"
    $a7="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}