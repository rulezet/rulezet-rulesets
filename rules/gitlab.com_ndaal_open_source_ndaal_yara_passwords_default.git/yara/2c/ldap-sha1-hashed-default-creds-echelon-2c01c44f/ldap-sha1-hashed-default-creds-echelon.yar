rule ldap_sha1_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}b2wsg6cxqfFUKkr7tF6gQ5xPRco="
    $a1="{SHA}b2wsg6cxqfFUKkr7tF6gQ5xPRco="
    $a2="{SHA}/2qp8tFh8PT66EIjVjQSlnSqIug="
    $a3="{SHA}yZ3znnj5XMv00/x9ISoPpa2QdCo="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}