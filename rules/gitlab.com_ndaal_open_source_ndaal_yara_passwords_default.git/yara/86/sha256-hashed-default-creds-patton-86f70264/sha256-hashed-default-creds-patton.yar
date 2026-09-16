rule sha256_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a1="7de97367c9cdc3c6db31aa114057b65cea1a7bafc71cf0595a2931011526a0a3"
    $a2="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
    $a3="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}