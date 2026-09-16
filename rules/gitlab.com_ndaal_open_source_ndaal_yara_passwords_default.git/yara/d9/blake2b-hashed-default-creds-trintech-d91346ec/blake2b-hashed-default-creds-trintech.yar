rule blake2b_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de4a5bc70779aefbfb8deddebde56b4868b9d438a9b856534cea96f123f8705eab29162659245d39df7cf93f5b49e124d4cde3494b4947008ab97b4179b82769"
    $a1="c2706534a4e08c444c758b85a91babd1fbc5f26829de718c2b0c336905567e15c8eea00577fa27c3e46c9bed1dc44ff7818c2c2354f3557c777cd8d9dc2223d9"
condition:
    ($a0 and $a1)
}