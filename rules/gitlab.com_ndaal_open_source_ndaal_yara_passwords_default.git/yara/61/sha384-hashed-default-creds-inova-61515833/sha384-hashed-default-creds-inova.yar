rule sha384_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e315184486f32c9d7c3e0fb4c8235553db7c564c8a32a89c2181410df8e5535d3b207e8351ae8f733a1c128423572a58"
    $a1="7c007479b667ab9a808550ee73ce9818541251ff9fb12540b867004ef659eabb1f12b4702e59f66d4e81f9bbc32e43c1"
condition:
    ($a0 and $a1)
}