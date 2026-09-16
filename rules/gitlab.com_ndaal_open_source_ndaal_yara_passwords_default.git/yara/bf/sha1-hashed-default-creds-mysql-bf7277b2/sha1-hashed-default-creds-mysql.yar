rule sha1_hashed_default_creds_mysql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mysql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="c530c3f4079a09f7804259002307b5e50c656d52"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="37a8bdbdfa00827514dfb924e4989caf9236801f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}