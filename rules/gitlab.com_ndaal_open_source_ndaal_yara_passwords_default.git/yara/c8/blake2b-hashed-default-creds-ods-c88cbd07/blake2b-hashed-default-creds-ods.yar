rule blake2b_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0beb24701b62b7f6cc14cafd06c56aa727b89892415fb14663d456e8c4dc02a0fc78fd8badf46a0950eddb392616044178ad63f9436c50f5145ef689547bf5f4"
    $a1="0beb24701b62b7f6cc14cafd06c56aa727b89892415fb14663d456e8c4dc02a0fc78fd8badf46a0950eddb392616044178ad63f9436c50f5145ef689547bf5f4"
condition:
    ($a0 and $a1)
}