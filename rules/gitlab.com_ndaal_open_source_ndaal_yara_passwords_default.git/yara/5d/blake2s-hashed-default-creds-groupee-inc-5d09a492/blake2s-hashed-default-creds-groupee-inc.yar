rule blake2s_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c14520c08e20f8aa5c6cdf93744a23c16862ef29ac30e2238d29489995471469"
    $a1="d2c7dc2ad84ac92c982b94d59933102631ad89a3075f3884568cce04cb27a2d2"
condition:
    ($a0 and $a1)
}