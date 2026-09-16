rule sha3_256_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e5184f08aea8115aed0c70e297c5a9b618aea4efe96f5fd87fce169dc020f6a"
    $a1="5e4d2874a8e089b5180b497f41a141122145b624ef72bde5ea9f78a4f8e9036e"
condition:
    ($a0 and $a1)
}