rule sha3_224_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a1="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a2="e616bc283a5c8eb1227ee4e01f2ad82fca197f6c1ba7e1bb77d51522"
    $a3="e616bc283a5c8eb1227ee4e01f2ad82fca197f6c1ba7e1bb77d51522"
    $a4="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a5="e616bc283a5c8eb1227ee4e01f2ad82fca197f6c1ba7e1bb77d51522"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}