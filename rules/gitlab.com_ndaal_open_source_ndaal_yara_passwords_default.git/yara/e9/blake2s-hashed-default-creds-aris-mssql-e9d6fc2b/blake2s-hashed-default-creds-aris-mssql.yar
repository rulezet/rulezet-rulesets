rule blake2s_hashed_default_creds_aris_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e67a399e6e3ce0012e6da0e1e87fa9e422f7feea894dce8c0cee8a0ec17f69ee"
    $a1="889e03fc1b469bb6b8da41b0e4022928fbfc1d9d4d62f8c227f0858000044e20"
condition:
    ($a0 and $a1)
}