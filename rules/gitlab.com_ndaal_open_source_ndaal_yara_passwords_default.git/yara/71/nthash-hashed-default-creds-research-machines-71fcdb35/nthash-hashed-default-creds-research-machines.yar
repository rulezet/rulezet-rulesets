rule nthash_hashed_default_creds_research_machines
{
    meta:
        id = "sPHdYmie04BVw4D03XJda"
        fingerprint = "153b4c3131f745b8478e4debb9a4f74500c412e8fcf7daca024a42a0ff4a4bcd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for research_machines."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="f938b53b982f22cd6b1c14ae10665480"
condition:
    ($a0 and $a1)
}