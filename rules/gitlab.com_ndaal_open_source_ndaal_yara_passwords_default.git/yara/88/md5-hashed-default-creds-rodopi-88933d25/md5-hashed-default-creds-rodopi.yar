rule md5_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90d42b3de77616364705accfed65423b"
    $a1="90d42b3de77616364705accfed65423b"
    $a2="e531431e371fc921cbcbe3f719ff37a9"
    $a3="e531431e371fc921cbcbe3f719ff37a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}