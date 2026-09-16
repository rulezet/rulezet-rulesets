rule sha3_224_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6fc0ad96d39def6ffe8297153fcbfb5631c7a1d5b2de79eb16e66c7"
    $a1="fbbab0892e4437ccc7d46d062ed777d2616802bf313480da4a2f6352"
condition:
    ($a0 and $a1)
}