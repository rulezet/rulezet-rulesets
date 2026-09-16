rule sha3_224_hashed_default_creds_supermicro_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for supermicro_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfbb56a314e406232e84144aa3b459691cc889b7b7d7406dcf2aeec1"
    $a1="cfbb56a314e406232e84144aa3b459691cc889b7b7d7406dcf2aeec1"
condition:
    ($a0 and $a1)
}