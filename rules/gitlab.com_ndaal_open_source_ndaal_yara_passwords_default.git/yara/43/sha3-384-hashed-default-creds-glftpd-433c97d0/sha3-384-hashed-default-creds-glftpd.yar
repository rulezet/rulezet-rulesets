rule sha3_384_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d01446bdf713e473c53a6f7ec46ec2416fa7b4e79d7fce948e3fedd9fdc17f1a17d5c66db2be47b6071fe0d6f80bec6"
    $a1="7d01446bdf713e473c53a6f7ec46ec2416fa7b4e79d7fce948e3fedd9fdc17f1a17d5c66db2be47b6071fe0d6f80bec6"
condition:
    ($a0 and $a1)
}