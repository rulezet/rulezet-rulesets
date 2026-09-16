rule md5_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="827ccb0eea8a706c4c34a16891f84e7b"
    $a1="ee11cbb19052e40b07aac0ca060c23ee"
    $a2="827ccb0eea8a706c4c34a16891f84e7b"
    $a3="a41a2b2821465528e01361dbc363b14b"
    $a4="827ccb0eea8a706c4c34a16891f84e7b"
    $a5="4b2a1529867b8d697685b1722ccd0149"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}