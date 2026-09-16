rule nthash_hashed_default_creds_ibm_imm_web
{
    meta:
        id = "1xdcDXLl6k4R4FsRxcafrt"
        fingerprint = "490b7943fb991948840dd355ca21a3962c0b8f2fb588751b8a06817962423bb5"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba829364e85a90058d72f743bf1f74d1"
    $a1="c4452ac93b5dd0f6140d139bb2fcf536"
condition:
    ($a0 and $a1)
}