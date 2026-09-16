rule sha512_hashed_default_creds_darkman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc586db59176a9cc8c36457c58c6e7808164aac4bc6939b25d82e599622d288a2c3a4e505a7d59930f8a9177d346807a848b7e1f7e7f94629d2c750f402d4ab5"
    $a1="cc586db59176a9cc8c36457c58c6e7808164aac4bc6939b25d82e599622d288a2c3a4e505a7d59930f8a9177d346807a848b7e1f7e7f94629d2c750f402d4ab5"
condition:
    ($a0 and $a1)
}