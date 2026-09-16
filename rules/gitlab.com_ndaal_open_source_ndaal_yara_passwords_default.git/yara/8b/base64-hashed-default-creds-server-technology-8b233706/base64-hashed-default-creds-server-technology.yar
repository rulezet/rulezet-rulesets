rule base64_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QURNTg=="
    $a1="YWRtbg=="
    $a2="R0VOMQ=="
    $a3="Z2VuMQ=="
    $a4="R0VOMg=="
    $a5="Z2VuMg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}