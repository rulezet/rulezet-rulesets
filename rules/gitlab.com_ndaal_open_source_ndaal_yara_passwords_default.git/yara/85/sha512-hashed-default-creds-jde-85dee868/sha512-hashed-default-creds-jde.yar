rule sha512_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ecc0e9f4b585ee6bdd9038fb3f282f783975c61be93ce1d450852d2af13888bf555550ba2f8d475cf7bd7123003d50a3d7f25a7da3d6dab1caa53a1e9ab5b74"
    $a1="3ecc0e9f4b585ee6bdd9038fb3f282f783975c61be93ce1d450852d2af13888bf555550ba2f8d475cf7bd7123003d50a3d7f25a7da3d6dab1caa53a1e9ab5b74"
condition:
    ($a0 and $a1)
}