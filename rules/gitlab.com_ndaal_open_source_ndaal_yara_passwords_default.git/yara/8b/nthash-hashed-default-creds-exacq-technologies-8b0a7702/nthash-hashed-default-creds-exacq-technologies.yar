rule nthash_hashed_default_creds_exacq_technologies
{
    meta:
        id = "5SKTD5DzMbiafwJqbvG54R"
        fingerprint = "2eac84742052e49b836c6f05e97ad4b259b70d2288598ec3e6d55283660ea804"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exacq_technologies."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f9aedf8ab38c8b46acd1b21502ad6999"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="ed4147caa2f4c34103032fe99ff0ce8a"
    $a3="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}