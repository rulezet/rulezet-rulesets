rule sha512_hashed_default_creds_beck_ipc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bd9648da32ac4d0c3bf472a3b75c5f0c1de4ce9988a8e49041f3bb4b3cff29c912e921731a5369a5b7a7caebae26782571e4599b01711ce7e55c95840a46bdb"
    $a1="0bd9648da32ac4d0c3bf472a3b75c5f0c1de4ce9988a8e49041f3bb4b3cff29c912e921731a5369a5b7a7caebae26782571e4599b01711ce7e55c95840a46bdb"
condition:
    ($a0 and $a1)
}