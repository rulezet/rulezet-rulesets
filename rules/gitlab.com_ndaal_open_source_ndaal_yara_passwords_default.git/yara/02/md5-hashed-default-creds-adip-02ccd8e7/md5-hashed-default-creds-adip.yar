rule md5_hashed_default_creds_adip
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adip."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="b504301092fbfe21c6a27f88768443bd"
    $a2="3d2e6bded046ca2e3f906f04235b279b"
    $a3="b504301092fbfe21c6a27f88768443bd"
    $a4="b7bd6536bf9b3071c642718c7a514eac"
    $a5="b504301092fbfe21c6a27f88768443bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}