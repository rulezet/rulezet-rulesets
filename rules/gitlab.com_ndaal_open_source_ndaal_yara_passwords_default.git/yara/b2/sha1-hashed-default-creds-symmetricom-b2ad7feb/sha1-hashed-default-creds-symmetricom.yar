rule sha1_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aaac9a3b5228e68ff255a846279cd5d9833952da"
    $a1="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a2="f3aa85ef72957869464b16e655dc3632217bb8d4"
    $a3="fe96dd39756ac41b74283a9292652d366d73931f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}