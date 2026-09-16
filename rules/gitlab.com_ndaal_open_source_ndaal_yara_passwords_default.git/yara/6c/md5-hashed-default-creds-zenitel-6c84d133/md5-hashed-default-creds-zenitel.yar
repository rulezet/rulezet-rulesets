rule md5_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b0939a5d0d3593b0945ca108905c41c"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="ff7d3b88d0c795de27b59f9c245dffa2"
    $a3="73acd9a5972130b75066c82595a1fae3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}