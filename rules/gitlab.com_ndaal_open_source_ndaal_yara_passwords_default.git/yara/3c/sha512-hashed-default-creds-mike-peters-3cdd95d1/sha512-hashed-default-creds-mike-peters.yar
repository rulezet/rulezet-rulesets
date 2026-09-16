rule sha512_hashed_default_creds_mike_peters
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67dacd5a4aa9d821189e70849feaf8f7e86b1f1bb6374025f34d0b7218c86b3bc065d8a14e0896f2d727f638d51494c56b85fb8596336610800773b59c81b50b"
    $a1="084464abfce48360589ea66600f6e515095aa719bd2df7bc15782d75c92b3084d150044fce39d114e3bebffc2a675d54dd1babf1e90a6e4fe1af5308aaf117ec"
condition:
    ($a0 and $a1)
}