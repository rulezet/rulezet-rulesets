rule sha256_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d13f712ce4df1ed57a45273c72b40466e9006a6a2092c7eed7f8c76ce586502"
    $a1="9d13f712ce4df1ed57a45273c72b40466e9006a6a2092c7eed7f8c76ce586502"
condition:
    ($a0 and $a1)
}