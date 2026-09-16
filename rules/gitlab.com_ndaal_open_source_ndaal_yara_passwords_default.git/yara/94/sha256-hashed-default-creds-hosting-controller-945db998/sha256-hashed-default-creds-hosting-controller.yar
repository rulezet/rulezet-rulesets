rule sha256_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9b71dca5b458fd1cc846601ff89e64600a67332a3119787c5299ad26769f9831"
    $a1="6b006a8bff111aa0eb05b4ea80e4148942cbf509ddc4f33598d8d9e4768089b4"
condition:
    ($a0 and $a1)
}