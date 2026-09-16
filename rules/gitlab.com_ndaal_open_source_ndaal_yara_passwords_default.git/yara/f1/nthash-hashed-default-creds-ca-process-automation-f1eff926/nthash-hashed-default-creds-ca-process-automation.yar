rule nthash_hashed_default_creds_ca_process_automation
{
    meta:
        id = "6iWnw6HMBtQoRSYWkEDtmo"
        fingerprint = "501c6c45311f60c5e48be5c1eceb303590b754a9c3dba222f797393d95c73114"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="39985f9396c536323f4a4839815cd5b0"
    $a1="39985f9396c536323f4a4839815cd5b0"
condition:
    ($a0 and $a1)
}