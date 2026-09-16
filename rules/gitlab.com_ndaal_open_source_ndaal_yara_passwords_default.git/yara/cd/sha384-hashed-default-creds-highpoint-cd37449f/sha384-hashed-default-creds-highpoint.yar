rule sha384_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8c9910f7849d5b1c25ef30db30482bd156954009738a4daff206fae810cc8a7bc1ffc7feba82a6a6d9ab036ce045117"
    $a1="f1a72ae40795fac6f63816d70241563f59041d64450e1ae3df824de7a4295ec4b2a0cc9dd29369c586ccd1d35480f61b"
condition:
    ($a0 and $a1)
}