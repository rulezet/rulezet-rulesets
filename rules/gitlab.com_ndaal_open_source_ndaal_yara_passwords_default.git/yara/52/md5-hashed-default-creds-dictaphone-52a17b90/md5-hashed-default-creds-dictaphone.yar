rule md5_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25835188a2355e9530d3a10fcbe4c65b"
    $a1="25835188a2355e9530d3a10fcbe4c65b"
    $a2="71740ec34cabbd03f03fb27be8aec352"
    $a3="71740ec34cabbd03f03fb27be8aec352"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}