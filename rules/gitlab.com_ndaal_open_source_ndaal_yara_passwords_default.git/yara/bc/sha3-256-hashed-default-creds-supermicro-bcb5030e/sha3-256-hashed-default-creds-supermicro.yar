rule sha3_256_hashed_default_creds_supermicro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for supermicro."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="aeae63318b23cc3826a1b396f8ce6c5b83c89629acc8e5ed6ff944eb21d047ed"
    $a2="aeae63318b23cc3826a1b396f8ce6c5b83c89629acc8e5ed6ff944eb21d047ed"
    $a3="aeae63318b23cc3826a1b396f8ce6c5b83c89629acc8e5ed6ff944eb21d047ed"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}