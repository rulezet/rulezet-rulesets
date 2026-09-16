rule sha1_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a1="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a2="7c67c769e5ba5b5e700e39a0b300e28101dc0468"
    $a3="7c67c769e5ba5b5e700e39a0b300e28101dc0468"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}