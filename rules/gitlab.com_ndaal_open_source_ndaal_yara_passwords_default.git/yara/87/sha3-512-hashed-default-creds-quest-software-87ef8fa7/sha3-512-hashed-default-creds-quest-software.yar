rule sha3_512_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="469182284c02cbfc6b34446a92ca5c9b5ee144eb494c3b04ae7f84c09762129f3b1dfb020a82b4a35fab49de4a1cd5ebccf6d2592ee8e53145e612d60a9f4f5a"
    $a1="469182284c02cbfc6b34446a92ca5c9b5ee144eb494c3b04ae7f84c09762129f3b1dfb020a82b4a35fab49de4a1cd5ebccf6d2592ee8e53145e612d60a9f4f5a"
condition:
    ($a0 and $a1)
}