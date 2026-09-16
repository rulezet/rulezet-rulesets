rule mysql41_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*223789B76D5FF103AFF6BE5048960E2C896DD842"
    $a1="*223789B76D5FF103AFF6BE5048960E2C896DD842"
    $a2="*ECF6F9EC4B299A3717A0478BE89346CCAE3D266F"
    $a3="*ECF6F9EC4B299A3717A0478BE89346CCAE3D266F"
    $a4="*88DB7E9ED285F6940F943544B7EF5FB6F2A2C795"
    $a5="*88DB7E9ED285F6940F943544B7EF5FB6F2A2C795"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}