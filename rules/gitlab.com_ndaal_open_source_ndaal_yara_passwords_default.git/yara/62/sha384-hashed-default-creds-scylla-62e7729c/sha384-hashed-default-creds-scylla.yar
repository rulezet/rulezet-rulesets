rule sha384_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15810a9125e6ee1ca865e0ad2a608a15d9248dd796b8103d3e843f31e7a84245e5c80611824d29a5c40844165765dcaf"
    $a1="15810a9125e6ee1ca865e0ad2a608a15d9248dd796b8103d3e843f31e7a84245e5c80611824d29a5c40844165765dcaf"
condition:
    ($a0 and $a1)
}