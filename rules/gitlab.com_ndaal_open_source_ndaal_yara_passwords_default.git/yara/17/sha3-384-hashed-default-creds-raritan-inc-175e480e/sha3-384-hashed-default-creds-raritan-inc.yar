rule sha3_384_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23aad933df4b3fa35477fe3eb824281ebe623c2bbb526a156ef17d235ddd38b8fc23e9adcba6a31b14fc623ae3e2219d"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="23aad933df4b3fa35477fe3eb824281ebe623c2bbb526a156ef17d235ddd38b8fc23e9adcba6a31b14fc623ae3e2219d"
    $a3="f31681e64e051c1505b9cfbe4bf37f01bcc36d7932b568b3a4105cb05aa8b8104769a048ad1f5e7271a24822fc2f3c25"
    $a4="80a47d0fb171ae6d635f79c29a4468941cfcd6a902b1cfd22a608965ab5b4a726280e1983096f90dafafd549ea38eb9e"
    $a5="7fcdac8be28ccbff986903ba79f3afa3bb981f8dd1aa64c977cb6aaa2fb13c26d055c5849de2e99e36a033eeb0f5c24c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}