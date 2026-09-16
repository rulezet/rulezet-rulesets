rule sha3_224_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9750540563f25903edc2f19cba4ab7a387ad8eadcc4bf6c5f29c8eb"
    $a1="a0d2175f9f9596a4047b20f01a9239385c2fc7822e61127d075d7e30"
    $a2="eb3dda4045565b3eec506bd3944eb6d6e3a3567e8b529a52fa5b8f22"
    $a3="a8e2d807caf86a6b68078256e81d65b4e4ad8196aa90a0d5f5d699a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}