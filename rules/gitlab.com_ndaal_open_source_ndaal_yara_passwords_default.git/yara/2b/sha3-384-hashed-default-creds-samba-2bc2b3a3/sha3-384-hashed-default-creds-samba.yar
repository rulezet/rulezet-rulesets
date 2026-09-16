rule sha3_384_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58cfccd6944bcc1b58986ea78c313b6891b1767b1f292a678ddb604c8a5be59ddcb6f6de45594db2355ac2e205947cb5"
    $a1="58cfccd6944bcc1b58986ea78c313b6891b1767b1f292a678ddb604c8a5be59ddcb6f6de45594db2355ac2e205947cb5"
condition:
    ($a0 and $a1)
}