rule sha224_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ec958cdcbe36c29d3c51fae261d36b15b0efdcb9f557a946dcb3c20"
    $a1="2ec958cdcbe36c29d3c51fae261d36b15b0efdcb9f557a946dcb3c20"
    $a2="2ec958cdcbe36c29d3c51fae261d36b15b0efdcb9f557a946dcb3c20"
    $a3="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}