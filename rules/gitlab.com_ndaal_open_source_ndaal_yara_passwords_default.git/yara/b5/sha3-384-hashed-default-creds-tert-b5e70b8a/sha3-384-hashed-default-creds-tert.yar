rule sha3_384_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24517746773eb352524f1250fa025cebeaa2baa050e81550b40220e48497e7448315d454ae790f23ea217bb1a74083f8"
    $a1="24517746773eb352524f1250fa025cebeaa2baa050e81550b40220e48497e7448315d454ae790f23ea217bb1a74083f8"
condition:
    ($a0 and $a1)
}