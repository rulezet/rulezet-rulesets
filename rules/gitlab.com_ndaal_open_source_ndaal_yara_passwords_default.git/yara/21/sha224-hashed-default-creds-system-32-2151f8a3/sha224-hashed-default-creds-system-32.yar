rule sha224_hashed_default_creds_system_32
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for system_32."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12"
    $a1="e183e77efe617016cee5bfcb2b093efa10cac183dbe53b6198729de6"
condition:
    ($a0 and $a1)
}