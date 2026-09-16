rule sha256_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a3="2e93f8045553c109d586f91d54e4902ff14dc793562a9d2ac2ca5bb86bce6ed9"
    $a4="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}