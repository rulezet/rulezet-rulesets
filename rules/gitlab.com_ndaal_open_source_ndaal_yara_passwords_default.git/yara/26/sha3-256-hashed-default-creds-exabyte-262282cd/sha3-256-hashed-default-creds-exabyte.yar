rule sha3_256_hashed_default_creds_exabyte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c791f4313dfcf9f2dfb6bf9effb059407b9cf8138f65c49400dee484de02786"
    $a1="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
condition:
    ($a0 and $a1)
}