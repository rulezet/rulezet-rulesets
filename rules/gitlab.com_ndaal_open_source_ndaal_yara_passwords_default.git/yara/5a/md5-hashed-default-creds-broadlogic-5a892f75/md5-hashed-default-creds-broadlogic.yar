rule md5_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="add6bb58e139be103324d04d82d8f545"
    $a1="add6bb58e139be103324d04d82d8f545"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="97384261b8bbf966df16e5ad509922db"
    $a5="97384261b8bbf966df16e5ad509922db"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}