rule sha1_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d2b1416920e30a9b93277505b94a1f38e7dd98f"
    $a1="0d2b1416920e30a9b93277505b94a1f38e7dd98f"
    $a2="85d73a45b6b80dce45ec16f90f601c261b869dd3"
    $a3="c6a4fe0b25a74497e966f279f5186c99e5ce30e3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}