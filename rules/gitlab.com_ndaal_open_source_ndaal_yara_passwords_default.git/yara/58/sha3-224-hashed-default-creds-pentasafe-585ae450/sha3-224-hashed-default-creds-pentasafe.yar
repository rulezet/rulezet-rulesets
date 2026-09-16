rule sha3_224_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1599a41ef24b84e81d72e5ffe03f5c46cf9a8b57f69028c5693f81b"
    $a1="cf477bb1d3037f2f398a5fb986c5755ce421df1f6541e5cda9a81904"
condition:
    ($a0 and $a1)
}