rule sha512_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cb4459fff9614cdfa35ea7300c2fd24132d71240efa5ead4b56581a4da3750472db10df848bd5b063e044d64c80316a63f679b491538b33767709b819640f59"
    $a1="0cb4459fff9614cdfa35ea7300c2fd24132d71240efa5ead4b56581a4da3750472db10df848bd5b063e044d64c80316a63f679b491538b33767709b819640f59"
condition:
    ($a0 and $a1)
}