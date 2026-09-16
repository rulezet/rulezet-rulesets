rule nthash_hashed_default_creds_omron
{
    meta:
        id = "3AjCgzCYfSudfE5bez4emr"
        fingerprint = "81b9880e30c1874878182d5e296c9f6a9d318dc3d91418f204dcf7c8ffc14137"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d891ab402caf2e89ccdd33ed54333ac"
    $a1="7d891ab402caf2e89ccdd33ed54333ac"
condition:
    ($a0 and $a1)
}