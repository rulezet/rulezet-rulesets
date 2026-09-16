rule nthash_hashed_default_creds_liquidware_labs_inc
{
    meta:
        id = "4bSQa5kjwhxqMMdydlhwXU"
        fingerprint = "192a8f739414a2cc02c6d6d8bb1103d0a23cc6282157ae12493f658047d499a4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e481edc2617c21af1fe8d38699da8803"
    $a1="0673a400c41ad5ca083e90502ee8d7df"
condition:
    ($a0 and $a1)
}