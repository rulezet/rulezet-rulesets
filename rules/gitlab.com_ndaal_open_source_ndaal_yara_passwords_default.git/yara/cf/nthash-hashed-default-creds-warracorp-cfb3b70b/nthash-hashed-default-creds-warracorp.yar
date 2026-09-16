rule nthash_hashed_default_creds_warracorp
{
    meta:
        id = "2w05R7ePMhSeHjX1jARXDI"
        fingerprint = "0caeaf1876df7fe34bca97a07971bc2f0e3cc3fdb0917a1c7320e63959edd9fc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cad94addbd9f3f41ca85f4d61225975f"
    $a1="cad94addbd9f3f41ca85f4d61225975f"
condition:
    ($a0 and $a1)
}