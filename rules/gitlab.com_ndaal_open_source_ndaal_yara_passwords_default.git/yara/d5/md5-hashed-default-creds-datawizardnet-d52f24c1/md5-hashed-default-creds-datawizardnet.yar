rule md5_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d76c441e7b50697b1cd21714d233fd8"
    $a1="294de3557d9d00b3d2d8a1e6aab028cf"
    $a2="100b8cad7cf2a56f6df78f171f97a1ec"
    $a3="294de3557d9d00b3d2d8a1e6aab028cf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}