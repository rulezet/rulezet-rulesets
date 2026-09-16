rule mysql41_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7E5AF00DC80420982D961E605545F58ACA163F4A"
    $a1="*7E5AF00DC80420982D961E605545F58ACA163F4A"
    $a2="*BE8F26262B1AF06C97FCD9CB10B28584065A915D"
    $a3="*BE8F26262B1AF06C97FCD9CB10B28584065A915D"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}