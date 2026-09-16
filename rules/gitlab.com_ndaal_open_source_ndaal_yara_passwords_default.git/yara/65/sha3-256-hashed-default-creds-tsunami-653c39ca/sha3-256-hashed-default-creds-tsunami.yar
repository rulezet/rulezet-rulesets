rule sha3_256_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f89fc42704de7715afe014d0af4923e83bce4bff3c83fb3a5f31f90f33a1ffa"
    $a1="6f89fc42704de7715afe014d0af4923e83bce4bff3c83fb3a5f31f90f33a1ffa"
condition:
    ($a0 and $a1)
}