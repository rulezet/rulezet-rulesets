rule sha384_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f176d95b83e3fad5d0bef9013d42e52b62de341c4bbab8fef12c2313d1350472f26d832dcb74d7bde47a7227d904b84b"
    $a1="62d35c44b07b37fa595e75f066f8aa1f8aeb5567bd99671e10603cc4a53c721a035e35cca06ba75d5c0ac42757ca84c8"
condition:
    ($a0 and $a1)
}