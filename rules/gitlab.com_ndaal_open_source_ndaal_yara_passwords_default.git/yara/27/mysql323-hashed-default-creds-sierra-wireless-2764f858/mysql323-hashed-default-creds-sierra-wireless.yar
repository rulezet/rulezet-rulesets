rule mysql323_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e782c85379a326e"
    $a1="1a486e7929011a28"
    $a2="2e782c85379a326e"
    $a3="58ed82ec387c581c"
    $a4="2e782c85379a326e"
    $a5="445c763436020c0e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}