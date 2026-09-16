rule sha3_224_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a1="68c512124eccb399e344ff38cfeba3bde7a7c356bff9b57fa2a70f2b"
condition:
    ($a0 and $a1)
}