rule sha3_224_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a1="b92a3adeccb43ee883a47a69447666a1243ec6b0b982cf2bad98ec9d"
    $a2="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a3="ef8a052d11cd0d6f18d856292b347369d8f7799f959f1fa65d7077de"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}