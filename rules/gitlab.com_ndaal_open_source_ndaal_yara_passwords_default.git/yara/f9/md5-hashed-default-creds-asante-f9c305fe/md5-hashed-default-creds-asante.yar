rule md5_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="420725238c9faf69d6dd60e951f67f60"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="420725238c9faf69d6dd60e951f67f60"
    $a3="0baea2f0ae20150db78f58cddac442a9"
    $a4="e8b84b9d2159cccb68ff18fb4995a73c"
    $a5="c273a18679ae66eb2ec3cefbb529d9d3"
    $a6="e8b84b9d2159cccb68ff18fb4995a73c"
    $a7="11da2a2a6126b4b0fd20d214feaf11f1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}