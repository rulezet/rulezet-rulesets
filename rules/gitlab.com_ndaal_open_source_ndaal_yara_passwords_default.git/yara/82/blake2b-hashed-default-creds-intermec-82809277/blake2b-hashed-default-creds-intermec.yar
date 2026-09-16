rule blake2b_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fd4eb614ffcd4399709a0796a335aef4fb0eff065d7688cb8b827bfe6b1bbbae6715b72515f61557b1cac2126bedcac5dbe51de372e2498fd533b001805e737"
    $a1="0fd4eb614ffcd4399709a0796a335aef4fb0eff065d7688cb8b827bfe6b1bbbae6715b72515f61557b1cac2126bedcac5dbe51de372e2498fd533b001805e737"
condition:
    ($a0 and $a1)
}