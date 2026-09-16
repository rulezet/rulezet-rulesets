rule sha224_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b61bb0c069dad82f93a41b2a3a08c324f4583e629168858c11cc9e63"
    $a1="b61bb0c069dad82f93a41b2a3a08c324f4583e629168858c11cc9e63"
    $a2="e2da4d2c46076de30800a2777d7d7ae6be36b64e39246c345ff93676"
    $a3="e2da4d2c46076de30800a2777d7d7ae6be36b64e39246c345ff93676"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}