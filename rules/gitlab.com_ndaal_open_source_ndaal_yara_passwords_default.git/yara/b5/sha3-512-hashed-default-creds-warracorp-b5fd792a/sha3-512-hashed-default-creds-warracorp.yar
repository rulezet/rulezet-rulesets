rule sha3_512_hashed_default_creds_warracorp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="839842bae789f42e3dba9f83709c02dc8c4f375e1ccb8bd5bd97c84ccda17c02e916d7a8d99f660a0cb78e6a338d1597e27ea07516ee1bf0cf412ea0c56fa41d"
    $a1="839842bae789f42e3dba9f83709c02dc8c4f375e1ccb8bd5bd97c84ccda17c02e916d7a8d99f660a0cb78e6a338d1597e27ea07516ee1bf0cf412ea0c56fa41d"
condition:
    ($a0 and $a1)
}