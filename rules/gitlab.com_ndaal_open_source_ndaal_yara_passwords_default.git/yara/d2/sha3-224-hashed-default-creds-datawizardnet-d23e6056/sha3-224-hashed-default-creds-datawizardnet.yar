rule sha3_224_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6bbf6d1d88b83d947de2db6432cf00c63086a94df29e86744db20e0e"
    $a1="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a2="1b80ba673a959ff153aa35c0bcf7bbc66aee780c7680fbb15a445c3a"
    $a3="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}