rule sha384_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d4cef224efed81a7a3b5bdd4048adad9b8cb98618ca87aaa23ffe45617f2aaf762cb67d8ecf9b00b1ef51888e4b9ee43"
    $a1="d4cef224efed81a7a3b5bdd4048adad9b8cb98618ca87aaa23ffe45617f2aaf762cb67d8ecf9b00b1ef51888e4b9ee43"
condition:
    ($a0 and $a1)
}