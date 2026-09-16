rule sha224_hashed_default_creds_seagull_scientific
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seagull_scientific."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="c417c5952fa1d63472b612f11e45809ea820ab918be37121fc257e6c"
    $a2="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
    $a3="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}