rule sha1_hashed_default_creds_supermicro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for supermicro."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="b521caa6e1db82e5a01c924a419870cb72b81635"
    $a2="b521caa6e1db82e5a01c924a419870cb72b81635"
    $a3="b521caa6e1db82e5a01c924a419870cb72b81635"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}