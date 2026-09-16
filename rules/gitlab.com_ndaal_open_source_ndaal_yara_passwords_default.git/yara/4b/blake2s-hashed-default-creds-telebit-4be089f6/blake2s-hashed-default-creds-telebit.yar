rule blake2s_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a1="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
    $a2="450c9a03e5369c74b49b59ffb044e8dfc50fdbc7caf31b3b40b17c6b0cc2ae50"
    $a3="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
    $a4="20c86bb90d595717f02c30e7e36eabf994dc72a5e99aa728bccd75e52495f52d"
    $a5="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}