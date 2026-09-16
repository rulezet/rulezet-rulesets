rule sha1_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25c5d184fd3c8e7d24af0e237c061f5480a5e86e"
    $a1="25c5d184fd3c8e7d24af0e237c061f5480a5e86e"
    $a2="f40b27d6b8b9a4fc3827264c1da16a04ecf4d094"
    $a3="f40b27d6b8b9a4fc3827264c1da16a04ecf4d094"
    $a4="37dc93df3b8a3da037e42cd0cb632352b36574ef"
    $a5="37dc93df3b8a3da037e42cd0cb632352b36574ef"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}