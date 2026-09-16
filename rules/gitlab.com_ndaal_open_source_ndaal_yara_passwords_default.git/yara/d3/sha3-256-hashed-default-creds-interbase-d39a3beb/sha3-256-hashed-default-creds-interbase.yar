rule sha3_256_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="479c8cc5b15e63edffa494719fb284525dcd351436ef9be5c6761eaead136c82"
    $a1="4bb99770fa21751eed6dd7496b1e3e1fc6e62b41ad403d90ca47f4feef023ffa"
condition:
    ($a0 and $a1)
}