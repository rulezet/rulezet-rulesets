rule sha3_256_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="623c5a5d9d7a4ae4f669448e0294f976cb09b58536b4d45d3917a593ce34d6d0"
    $a1="67974796ed393c0edaca0023b3efd3d2f56130b13b5813354624c500cfd56b95"
    $a2="24af0329dd22bcdf3805f1fdd579b30681ebe2c4c0b89eceb528158b64cced67"
    $a3="67974796ed393c0edaca0023b3efd3d2f56130b13b5813354624c500cfd56b95"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}