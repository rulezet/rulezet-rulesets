rule md5_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97bff26855a8bfa63e05d5477e794b24"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="02c86eb2792f3262c21d030a87e19793"
    $a3="02c86eb2792f3262c21d030a87e19793"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}