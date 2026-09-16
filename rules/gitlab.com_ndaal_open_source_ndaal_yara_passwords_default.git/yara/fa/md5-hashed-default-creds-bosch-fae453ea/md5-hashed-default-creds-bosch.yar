rule md5_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aaabf0d39951f3e6c3e8a7911df524c2"
    $a1="aaabf0d39951f3e6c3e8a7911df524c2"
    $a2="d0dbe915091d400bd8ee7f27f0791303"
    $a3="d0dbe915091d400bd8ee7f27f0791303"
    $a4="ee11cbb19052e40b07aac0ca060c23ee"
    $a5="ee11cbb19052e40b07aac0ca060c23ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}