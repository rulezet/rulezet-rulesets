rule sha3_384_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="227e8bec444f05d5459fff38cd02b171ecd52fcf3b62932ce65c7a9c7a804bbcfc6b521fb85cba8edc4bbb3e4f74de03"
    $a1="227e8bec444f05d5459fff38cd02b171ecd52fcf3b62932ce65c7a9c7a804bbcfc6b521fb85cba8edc4bbb3e4f74de03"
condition:
    ($a0 and $a1)
}