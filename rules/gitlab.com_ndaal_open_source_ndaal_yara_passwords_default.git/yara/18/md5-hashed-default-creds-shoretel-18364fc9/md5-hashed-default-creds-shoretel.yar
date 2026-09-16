rule md5_hashed_default_creds_shoretel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for shoretel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cb9c8a8048fd02294477fcb1a41191a"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="e00cf25ad42683b3df678c61f42c6bda"
    $a3="e3afed0047b08059d0fada10f400c1e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}