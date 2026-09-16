rule sha384_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="990addf057c1486caefc14c4dbc336290dcf2adb007f2593b8bb4ab80bc3a23ec044b3b0bb51df119e3e46285bbf3d66"
    $a1="4db4b0c1da6e12f24d1eb30c2b1cd56a4b478b964e34031aeedb2043a4369ba9a3c11f16b0499290cf6c04d0b15e5659"
condition:
    ($a0 and $a1)
}