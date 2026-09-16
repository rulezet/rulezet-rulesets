rule md5_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="07ded64f812afb8da181014a9d087728"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="c80cc0537e6c13e09a296dd19594aea0"
    $a3="43b90920409618f188bfc6923f16b9fa"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}