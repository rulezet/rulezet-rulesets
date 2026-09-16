rule sha384_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e71fed31722985ecf8213ecaf2d63bb8c71e6f64bdde6c01c5914e9570cd813cc5023361b38b6504ff60d2b09b8e54cf"
    $a1="e71fed31722985ecf8213ecaf2d63bb8c71e6f64bdde6c01c5914e9570cd813cc5023361b38b6504ff60d2b09b8e54cf"
condition:
    ($a0 and $a1)
}