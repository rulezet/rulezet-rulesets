rule blake2s_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cd1b45ddbcb86bb8a889f7faec5091741d32f1394a0b4c7113e461c6d89366d"
    $a1="652668a5992e8059aeb54f618c3ef4663dddace1e4243b92143ee261cf6ac1ef"
condition:
    ($a0 and $a1)
}