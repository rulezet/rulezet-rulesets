rule sha384_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e85d2fdb8cab77a9bac7a917af0c70054b4e912cd654abb679ca059157f386bf534a808a0b6bd2e0a00f99a9dd6d8d49"
    $a1="dac32cd47547c127b8724766d1f4b77b9ea53639e84c7d07268f6969aea80513134ae77aceae74a444deb3ad62db1f3b"
condition:
    ($a0 and $a1)
}