rule md5_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="674f3c2c1a8a6f90461e8a66fb5550ba"
    $a1="c2ba7e785c49050f48da9aacc45c2b85"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="4b583376b2767b923c3e1da60d10de59"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}