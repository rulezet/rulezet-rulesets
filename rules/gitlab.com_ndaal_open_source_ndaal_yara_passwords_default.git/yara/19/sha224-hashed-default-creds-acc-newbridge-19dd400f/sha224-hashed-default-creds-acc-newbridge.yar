rule sha224_hashed_default_creds_acc_newbridge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc_newbridge."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
    $a1="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
condition:
    ($a0 and $a1)
}