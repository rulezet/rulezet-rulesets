rule sha3_256_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9001e1a9258d57e0e61b8222a25a04927b12ed41eb39364f180eb5d7bdd8a937"
    $a1="789cf532419e99b67093f10b9059465900d073c466c25efd00771189d38f7e66"
    $a2="6bb4c8e14fe4dc77a7a27a5d75c181cffa632c0c2907086c0f67fb9a55016b96"
    $a3="6bb4c8e14fe4dc77a7a27a5d75c181cffa632c0c2907086c0f67fb9a55016b96"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}