rule sha3_224_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c76a4df1b64a64bced13df71c61575ce6c2dbdde9eb03e3ea1a9d9ef"
    $a1="c76a4df1b64a64bced13df71c61575ce6c2dbdde9eb03e3ea1a9d9ef"
condition:
    ($a0 and $a1)
}