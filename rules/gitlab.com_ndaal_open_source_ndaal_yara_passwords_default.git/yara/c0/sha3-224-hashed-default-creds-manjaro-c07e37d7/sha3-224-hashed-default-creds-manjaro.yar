rule sha3_224_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa1a3e928132dbcde7415d71081e408e6ab793b2978aa52f578e7ae0"
    $a1="20eb8970892df6a888f6dfdcd32ff9d194a155fa66cee9f9c4eda8fe"
    $a2="d268ffa2d566bfdb8323d78507a07ffd01e01596ee5295c134e803a3"
    $a3="20eb8970892df6a888f6dfdcd32ff9d194a155fa66cee9f9c4eda8fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}