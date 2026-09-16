rule sha256_hashed_default_creds_beck_ipc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="41495646594ce2b35ac5fb30ccef91d9344cdc5377a78fef035a2901557ba5b2"
    $a1="41495646594ce2b35ac5fb30ccef91d9344cdc5377a78fef035a2901557ba5b2"
condition:
    ($a0 and $a1)
}