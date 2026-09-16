rule sha3_512_hashed_default_creds_liquidware_labs_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8854e95de857e02c5259d91607b4262d094d5a6306d9d88e70c49c984bbc35e2deeb92fdad75f8c6e9c72957c9093a82a38217d7056a3f47e1cf6e42102965aa"
    $a1="7434076f4e91d703b1736ab561218a6de6dfdd1e67d8b18329e044e59a72ce534c3e5c2d61904b8ecc39aac465ac276d2f1d33158face0df07ea3340a29d70a1"
condition:
    ($a0 and $a1)
}