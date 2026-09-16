rule nthash_hashed_default_creds_esesix_computer_gmbh
{
    meta:
        id = "emCfwWs7XgUrswVYUWlq0"
        fingerprint = "4121a94e64106e4cb3491f90dd45a6280139c920fbe9709a1c53262f60cf9702"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for esesix_computer_gmbh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="107464259015712f61d201f8ce571b67"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}