rule sha224_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a5fcaa8156df5fc8f006e239b44d01fd54862cee3056ef9ece150db"
    $a1="c63484920f98fc2d476054699e79b0b05747087251f5b2a2828952cb"
    $a2="ea6f7d82eeefde0a23050c5d1a719c6f4df06e471f5ad667da5ce48e"
    $a3="ea6f7d82eeefde0a23050c5d1a719c6f4df06e471f5ad667da5ce48e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}