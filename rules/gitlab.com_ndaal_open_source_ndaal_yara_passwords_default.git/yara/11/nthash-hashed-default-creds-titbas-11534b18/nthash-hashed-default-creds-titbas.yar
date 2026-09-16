rule nthash_hashed_default_creds_titbas
{
    meta:
        id = "2SSAoAh9B6ALPiJbZmV4W5"
        fingerprint = "aad583ef739b3c61516d6a4d69cb8f5e27fc71aacbe895c9642ed17d92a8b568"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c345ef38a826f84633a9f4147bb49c31"
    $a1="f8b0c34035173351f6ecbe70d58a2024"
condition:
    ($a0 and $a1)
}