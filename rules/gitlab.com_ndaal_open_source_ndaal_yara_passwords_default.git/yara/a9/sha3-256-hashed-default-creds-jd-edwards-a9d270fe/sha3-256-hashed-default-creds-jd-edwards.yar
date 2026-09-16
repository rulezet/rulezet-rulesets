rule sha3_256_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="79f94a2bbc86bc6b3dac27793cf574d3d9733f31d689721a191d3d9efc93d696"
    $a1="79f94a2bbc86bc6b3dac27793cf574d3d9733f31d689721a191d3d9efc93d696"
condition:
    ($a0 and $a1)
}