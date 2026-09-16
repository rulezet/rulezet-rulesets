rule sha3_512_hashed_default_creds_telco_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telco_systems."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91026640bf22bb6596c215a764554a0eb1325cb01bfd71596d33cac1514965578a313eda1f8b48a4e9637f5e27577a4cdea8ef211086b8e28a4e4ab3e77019ba"
    $a1="91026640bf22bb6596c215a764554a0eb1325cb01bfd71596d33cac1514965578a313eda1f8b48a4e9637f5e27577a4cdea8ef211086b8e28a4e4ab3e77019ba"
condition:
    ($a0 and $a1)
}