rule sha224_hashed_default_creds_rabbitmq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rabbitmq."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a1="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
condition:
    ($a0 and $a1)
}