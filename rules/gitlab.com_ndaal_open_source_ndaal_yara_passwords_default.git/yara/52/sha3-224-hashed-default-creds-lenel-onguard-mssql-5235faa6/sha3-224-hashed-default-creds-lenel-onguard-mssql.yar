rule sha3_224_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e2e01fb78c2a92d5f462ce85ee9fd82858309f15049372e66d51b81"
    $a1="59350530052b856bf488a93df4a284d6e9e18b37d24d60b02e5e79d1"
condition:
    ($a0 and $a1)
}