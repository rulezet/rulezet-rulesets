rule sha3_224_hashed_default_creds_arun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for arun."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13f01cad4ba018bac1e9f01267f6e617adbd4a535b276e74ce58d4dc"
    $a1="602bdc204140db016bee5374895e5568ce422fabe17e064061d80097"
condition:
    ($a0 and $a1)
}