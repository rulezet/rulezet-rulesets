rule sha1_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b5bb4926a44c895a0535765e1618d60c9901e22"
    $a1="3b5bb4926a44c895a0535765e1618d60c9901e22"
    $a2="096146a66f76f2850d6527e14dfb1fad8985469a"
    $a3="d7bf229e01b21e0c521cb80b26bf24bd0f1d72db"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}