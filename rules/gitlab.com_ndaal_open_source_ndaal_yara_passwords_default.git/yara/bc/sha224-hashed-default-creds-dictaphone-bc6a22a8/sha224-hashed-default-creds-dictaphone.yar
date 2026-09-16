rule sha224_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab88a05dabbdd79168edc1d36d7e1f026c7144cb85792701611576f7"
    $a1="ab88a05dabbdd79168edc1d36d7e1f026c7144cb85792701611576f7"
    $a2="5e982cc7a14b30196bc347ee60b91fd0b4a1647814dfd8894cc5f9e8"
    $a3="5e982cc7a14b30196bc347ee60b91fd0b4a1647814dfd8894cc5f9e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}