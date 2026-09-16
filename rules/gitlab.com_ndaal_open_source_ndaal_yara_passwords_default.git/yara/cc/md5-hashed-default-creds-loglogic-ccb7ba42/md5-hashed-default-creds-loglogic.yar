rule md5_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29b2080676f3716c6cdde7b14b2b47bd"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="29b2080676f3716c6cdde7b14b2b47bd"
    $a3="7b24afc8bc80e548d66c4e7ff72171c5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}