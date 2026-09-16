rule sha3_512_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="210ff9ba45400c38132689d1cf71e3b077947830835ddbf675d59f3ef191e3ab89fe4687b43a08aefc7c029df5c9e711836dc7d2953c9b938b100deb794ce3a6"
    $a1="210ff9ba45400c38132689d1cf71e3b077947830835ddbf675d59f3ef191e3ab89fe4687b43a08aefc7c029df5c9e711836dc7d2953c9b938b100deb794ce3a6"
condition:
    ($a0 and $a1)
}