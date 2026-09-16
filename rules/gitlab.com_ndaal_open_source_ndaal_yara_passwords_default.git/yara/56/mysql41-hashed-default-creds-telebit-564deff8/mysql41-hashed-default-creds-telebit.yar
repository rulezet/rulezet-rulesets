rule mysql41_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a1="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a2="*2309AA61C73F02E54890747EAD6FFCB927A66565"
    $a3="*A5AEBB616D92AE56DC05FE583CE000F34072E007"
    $a4="*6F2192D95FC8369B70A989445154CD58E7D34C7C"
    $a5="*A5AEBB616D92AE56DC05FE583CE000F34072E007"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}