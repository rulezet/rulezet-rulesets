rule sha512_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="969007cf547f17098c25450f246323ff75f1f4d9a97c4c06d7e699a8d550834e64532ae64e2d9430d89f2908ef8e1855c9313e3bbfb464dc6a5df4e6a491dcb6"
    $a1="4f592225c67285e75102b2b3bbff9b41733a69929a139658b4acd846fea9c16b8d6c1de3696d46dd1a08bde89e441e7e7399fd319dc85d975215b21016bb85ba"
condition:
    ($a0 and $a1)
}