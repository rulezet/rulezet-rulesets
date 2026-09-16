rule sha1_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6845c6d90585c24d63de266c9a6da04090ed2dc2"
    $a1="6845c6d90585c24d63de266c9a6da04090ed2dc2"
    $a2="6a60619c25939a45374937d08ce674389e3d7765"
    $a3="6a60619c25939a45374937d08ce674389e3d7765"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}