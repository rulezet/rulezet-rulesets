rule sha256_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="96650eeb783b6ef504e6011c460f8bd9d64ff57c15d162cc5ad2be4f473059db"
    $a1="96650eeb783b6ef504e6011c460f8bd9d64ff57c15d162cc5ad2be4f473059db"
condition:
    ($a0 and $a1)
}