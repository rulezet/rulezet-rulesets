rule nthash_hashed_default_creds_fujitsu_siemens
{
    meta:
        id = "6qfQ2PIGKDk4ompMNPmJTU"
        fingerprint = "10b37e0a99589aa80f4200eb1d368537d3b598b70421fac11b3a2137860580bd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f9f7a4752abfcdee30587cfa4c2d803"
    $a1="be85ca9e6c44e05c9b2b50d681186a35"
condition:
    ($a0 and $a1)
}