rule sha3_256_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="479c8cc5b15e63edffa494719fb284525dcd351436ef9be5c6761eaead136c82"
    $a1="20615eac5ea29f807c12ce867d1e642cebf25b1f634a30e67fda9ec159f8fb08"
    $a2="083879a0735954f146f5331c90806948ed3dd6ddf7503c8106ec47769da20480"
    $a3="083879a0735954f146f5331c90806948ed3dd6ddf7503c8106ec47769da20480"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}