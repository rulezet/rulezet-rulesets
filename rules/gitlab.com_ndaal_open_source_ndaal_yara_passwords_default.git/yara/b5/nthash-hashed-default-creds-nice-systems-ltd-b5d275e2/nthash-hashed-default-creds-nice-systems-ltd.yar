rule nthash_hashed_default_creds_nice_systems_ltd
{
    meta:
        id = "3425kVn8I5SW9rVvGru3DX"
        fingerprint = "657612157b738759a832158bf3c0119be4f4b59fc876b51f9f30545c1b58fd82"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="180eda34968bb5515ec1a6bbf29cc257"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="180eda34968bb5515ec1a6bbf29cc257"
    $a3="333f2904481e5ffbb5064955973a5d9a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}