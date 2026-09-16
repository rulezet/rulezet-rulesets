rule nthash_hashed_default_creds_intersystems
{
    meta:
        id = "1lfjP3ggQOEWxI1AYOzJ32"
        fingerprint = "fc6ced93913a04a2435eefb5c53507f6a1d5da93373c256f32abfcd97c2cc41a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intersystems."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4fd0ab5b46db3d4bae053b78d3345800"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1)
}