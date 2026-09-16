rule sha384_hashed_default_creds_fortinet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="8d0bc3d36a50936cba4b2800da32086ae1389a30daf8332d11150bf5d390cbdb88cdfeae1691889b025270f10569762e"
    $a2="0d21f8b6dac36286304b5111712f4273d1bfcb6460ab07324598661fbefc4f5628b82676ebb54a8093a85f1b2fdbd46f"
    $a3="8d0bc3d36a50936cba4b2800da32086ae1389a30daf8332d11150bf5d390cbdb88cdfeae1691889b025270f10569762e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}