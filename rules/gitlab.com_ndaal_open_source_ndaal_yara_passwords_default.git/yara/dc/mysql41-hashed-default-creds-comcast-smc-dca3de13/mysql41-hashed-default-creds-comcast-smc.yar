rule mysql41_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9A637E32641F197A492E507BE597053098442199"
    $a1="*8CC79B5FDA8D438648AE41FD2B305F0967FF0F44"
    $a2="*B5BCA08DEF0B4B50A063686469C75E1E98EA172E"
    $a3="*8CC79B5FDA8D438648AE41FD2B305F0967FF0F44"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}