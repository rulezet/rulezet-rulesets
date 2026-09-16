rule sha1_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b1a13bf0f73d84955c28e8c1d35ae18701dd91d8"
    $a1="780ce71b10160b23f5a7ce4e2a094d9c06e33398"
    $a2="388b7f1f938cfa07c12296f832b1e6cca6dabd81"
    $a3="55679234f1f665aa88ff02ed238833b096b99693"
    $a4="56aaf2aa9eb2faffeb54679f530580b1c4aafe5c"
    $a5="09dcab79f53da5793de73bae09ccb325c98eded5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}