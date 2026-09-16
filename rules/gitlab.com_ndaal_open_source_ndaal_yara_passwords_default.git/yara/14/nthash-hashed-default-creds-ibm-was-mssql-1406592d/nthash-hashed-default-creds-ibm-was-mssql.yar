rule nthash_hashed_default_creds_ibm_was_mssql
{
    meta:
        id = "1pIOBa05qLMlQyrtylK2uz"
        fingerprint = "0bb7c7b3ef1b272cd6570ee74709c0bc61e46bee1374162f4504c6ef02db1fa4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b786125cfe6b75b17a4fc99c5bd6990b"
    $a1="b786125cfe6b75b17a4fc99c5bd6990b"
condition:
    ($a0 and $a1)
}