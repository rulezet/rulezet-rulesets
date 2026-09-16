rule nthash_hashed_default_creds_medocheck_mssql
{
    meta:
        id = "4m211XBq8tj082h9UpydAS"
        fingerprint = "653977ffd4590d0c87e3320a1c733408b45446f6a1b56b61d3ab7c9c950556b5"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c08ad4c3e5e2e29a6a13af912572f007"
    $a1="63cd80e86b901f4b117c56a6baa6a28f"
condition:
    ($a0 and $a1)
}