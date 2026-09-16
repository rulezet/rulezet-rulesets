rule sha3_224_hashed_default_creds_fortinet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="8a6ee7a6e59c5ee453a7674f284daf3c259f929a6c8a9094e546d406"
    $a2="14301f0a1a6ab60d13bf14c289098ceb361a15448bc5eb3069c52551"
    $a3="8a6ee7a6e59c5ee453a7674f284daf3c259f929a6c8a9094e546d406"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}