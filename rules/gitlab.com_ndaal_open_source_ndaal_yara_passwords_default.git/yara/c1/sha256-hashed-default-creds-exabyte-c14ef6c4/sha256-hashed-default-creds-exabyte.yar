rule sha256_hashed_default_creds_exabyte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea0a9bae9615b004baf583c525e7f4afd2d394d527bdbe294395523edebbefa4"
    $a1="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
condition:
    ($a0 and $a1)
}