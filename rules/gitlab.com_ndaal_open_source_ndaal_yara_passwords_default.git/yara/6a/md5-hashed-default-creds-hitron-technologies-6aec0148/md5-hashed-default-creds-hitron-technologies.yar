rule md5_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="3a31aeb5fab860cbad9a08350c14d1fe"
    $a3="f9dae9179218966b8f729aae0ddac437"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="257c2d1a0423a6a7c108632a8f963932"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}