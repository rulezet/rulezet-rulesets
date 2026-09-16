rule sha3_256_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2"
    $a1="4373fcd0735804b36f178e222653a7dee35415aa96572b029312c70b16546e71"
    $a2="67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2"
    $a3="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}