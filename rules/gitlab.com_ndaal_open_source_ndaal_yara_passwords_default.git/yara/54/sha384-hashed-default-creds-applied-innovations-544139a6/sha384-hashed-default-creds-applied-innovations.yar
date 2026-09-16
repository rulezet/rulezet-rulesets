rule sha384_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba214cabc52159fa3e4da4c89e33124c74596c795112f1a691847c11d6addaa7600186419f47a8b367ab1de496fa55af"
    $a1="ba214cabc52159fa3e4da4c89e33124c74596c795112f1a691847c11d6addaa7600186419f47a8b367ab1de496fa55af"
condition:
    ($a0 and $a1)
}