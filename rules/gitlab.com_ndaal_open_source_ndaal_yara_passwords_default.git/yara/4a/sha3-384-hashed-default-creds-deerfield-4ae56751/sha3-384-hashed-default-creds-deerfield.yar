rule sha3_384_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="942778443c50a9adcae42c5ef6ddf0e3364f34be60092bb2058242d6582fd785ea12c6dfc612594a9efbf95c59233645"
    $a1="02051756a91cfe4d2602f7be1b2ddb7dd30add4ae84fe6d9902532b0af9008a03651510afa54fc6b22e004a8c2689e9c"
condition:
    ($a0 and $a1)
}