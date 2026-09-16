rule sha512_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b79efb4932867d8e3d3822eeb101a8bd895a07d69c61786120e87a310d3f8ffd8896215facfc6a5aba7d3f7aa7325f98cf18183d43ddc5619a45e69b26344bf5"
    $a1="d35ec50a04360d3b42002a0449ddafaccac23660b071ccc561c299566bca611b630f215011eaffd2969539fc1619c661ed4d26573e83ce640bd5ac32ebc5b9ff"
condition:
    ($a0 and $a1)
}