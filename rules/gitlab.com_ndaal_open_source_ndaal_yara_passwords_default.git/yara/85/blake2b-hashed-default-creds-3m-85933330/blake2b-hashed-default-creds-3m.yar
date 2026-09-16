rule blake2b_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b74107dc535dbd829045bc54050ec629f9b8f39e8e04e3d267fd93cb06384d5366447caa4808dcc5b258edd1935d4119cc322aab0fbf0f5a4f4bfaee990aa2d4"
    $a1="b74107dc535dbd829045bc54050ec629f9b8f39e8e04e3d267fd93cb06384d5366447caa4808dcc5b258edd1935d4119cc322aab0fbf0f5a4f4bfaee990aa2d4"
condition:
    ($a0 and $a1)
}