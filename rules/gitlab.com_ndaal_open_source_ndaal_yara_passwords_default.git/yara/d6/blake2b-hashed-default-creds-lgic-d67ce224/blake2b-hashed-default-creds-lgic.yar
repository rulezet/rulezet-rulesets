rule blake2b_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80cb914358dfb5866c37c3ebc7ec62d34900e4a3ca85222c0cb6dc5ddf345b64e030fa55a15ebed6a2cea3c76fe16d7599fbd892a03c102afe373601382f9957"
    $a1="80cb914358dfb5866c37c3ebc7ec62d34900e4a3ca85222c0cb6dc5ddf345b64e030fa55a15ebed6a2cea3c76fe16d7599fbd892a03c102afe373601382f9957"
condition:
    ($a0 and $a1)
}