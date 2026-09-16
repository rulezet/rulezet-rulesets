rule sha3_224_hashed_default_creds_exabyte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8770903a6316e9f979ba990830ccd1c24fc5de37d8292fb591b99127"
    $a1="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
condition:
    ($a0 and $a1)
}