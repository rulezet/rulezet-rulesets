rule sha3_256_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="915e23ffde9980f2b7ac38bbdcc40dacf01de5fedbd9744324873b22e1b38dc6"
    $a1="915e23ffde9980f2b7ac38bbdcc40dacf01de5fedbd9744324873b22e1b38dc6"
condition:
    ($a0 and $a1)
}