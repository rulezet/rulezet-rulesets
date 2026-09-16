rule sha224_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bb36f76d5dd7ce9fb5d658f3c9b8a64c1dd23a6cb90709ec3dc5380c"
    $a1="78b54c128abb67fb08761f4200c3fe47f07e15be91efa0cd29343d9c"
condition:
    ($a0 and $a1)
}