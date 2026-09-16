rule mysql41_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B50E2145223248E53BE5E471F410CF5E9DA99983"
    $a1="*1FB07FA4B6F61E1EA743444B16F2D4635CD40C2D"
    $a2="*0B304F30352992829154580CE27AC37FE1BBE32D"
    $a3="*2B9A8B2E39799CE3F1C5AC3159444B684625C6BF"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}