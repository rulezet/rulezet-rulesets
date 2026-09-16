rule md5_hashed_default_creds_deif
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deif."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85d6705fd8f962c86779053f310f0cdc"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="c21f969b5f03d33d43e04f8f136e7682"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}