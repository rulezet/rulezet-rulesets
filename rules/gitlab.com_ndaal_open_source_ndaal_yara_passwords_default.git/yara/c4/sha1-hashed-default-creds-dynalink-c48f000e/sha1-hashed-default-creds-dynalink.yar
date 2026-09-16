rule sha1_hashed_default_creds_dynalink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="e80721793c24ae14edfca9b26ad406a9815cd3ff"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="3204a4c4ef9fecf14c8456a534eb6f36a9fd9713"
    $a5="65825c4e0ac64838553eecc1db4183a0712c5433"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}