rule sha3_384_hashed_default_creds_metro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metro."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a1="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
condition:
    ($a0 and $a1)
}