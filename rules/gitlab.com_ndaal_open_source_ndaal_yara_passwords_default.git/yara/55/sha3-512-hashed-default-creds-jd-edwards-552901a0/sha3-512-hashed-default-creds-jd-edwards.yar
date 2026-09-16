rule sha3_512_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b512bb3767004c6f6adcd9e9cb4399483b26f035834d1d7427ef3edee6ca5d3be8f2f1de3265a1e44f4ff644e7733e9ef13361c72649d3d8fdbff688d546b7c9"
    $a1="b512bb3767004c6f6adcd9e9cb4399483b26f035834d1d7427ef3edee6ca5d3be8f2f1de3265a1e44f4ff644e7733e9ef13361c72649d3d8fdbff688d546b7c9"
condition:
    ($a0 and $a1)
}