rule sha512_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f4d38cbe29495795948267dc429ce4b62e955ec2bf26fb48f0312959a71ecdad4523462c1f216bfc68b28ef18e8f84cc3b3a1c410edf711c93bab1b86b33297"
    $a1="4a066e718cf5276324b77c84f582020e30f764fcc163cdbdfc65868fb8fd526b36b6159fa3699004580c99c77277fda3f8442b428b5ed0fd58fdfaceabddfa9b"
condition:
    ($a0 and $a1)
}