rule sha3_384_hashed_default_creds_myiosoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for myiosoft."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a1="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
condition:
    ($a0 and $a1)
}