rule sha224_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f621e1bba28e252c957222ef06aa6c546521a05eff43fd4efb51b289"
    $a1="4e0bc09be74f54e27f0fbe9beec12d9e3019167cecb1938795e3ce75"
condition:
    ($a0 and $a1)
}