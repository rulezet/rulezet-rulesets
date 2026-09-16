rule sha3_512_hashed_default_creds_acc_newbridge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc_newbridge."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
    $a1="f96b8c19c3e7f114833925bce79968bd9e75b8f15f3a6cd3858ceae6a97105fa0a22911ba45b9ab8cf840b447848e447a40c65a6b39457b979172633572b1ea0"
condition:
    ($a0 and $a1)
}