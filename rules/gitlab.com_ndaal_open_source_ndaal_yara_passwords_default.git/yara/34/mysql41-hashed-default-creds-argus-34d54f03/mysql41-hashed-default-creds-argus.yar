rule mysql41_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E12CD91AC8FA1DC769505B9F283FAD0EC04AEE24"
    $a1="*E2A47DFFDB3F256BDE9A1D2753DB6D110B3F29C9"
    $a2="*C356E4DA244D8C098B598F140BBDEFB8690ED779"
    $a3="*C356E4DA244D8C098B598F140BBDEFB8690ED779"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}