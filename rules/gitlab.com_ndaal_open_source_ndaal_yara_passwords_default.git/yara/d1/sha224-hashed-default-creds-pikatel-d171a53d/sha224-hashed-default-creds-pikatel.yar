rule sha224_hashed_default_creds_pikatel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pikatel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bf38708bbfd108f71d4e225ad124e7a8437ec83e7020ec92206d08ff"
    $a1="bf38708bbfd108f71d4e225ad124e7a8437ec83e7020ec92206d08ff"
condition:
    ($a0 and $a1)
}