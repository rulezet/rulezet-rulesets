rule blake2b_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99e1746aeb43c221d34500c7963576d2a39ab92b8baf1894f6c544ccbed77f968797f4b6333eb5d2a5cbee7d0525adfcf99eab24a1d25e0e17a97911695eaa25"
    $a1="9e3a140ae1f7f2af37a52f77a8714cc420d3d17553fa8e7a5ee9af4cac8961ab4829b5aa7b3208c7394158bd4d80cda865a5f1ac9fa00bfe5fa344970a231b52"
condition:
    ($a0 and $a1)
}