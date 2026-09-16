rule sha256_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54d5cb2d332dbdb4850293caae4559ce88b65163f1ea5d4e4b3ac49d772ded14"
    $a1="dfbb2ff38689713c43a078485eaf6ddb34c0a1d9e5f774d1b06f7c0ebead7e60"
condition:
    ($a0 and $a1)
}