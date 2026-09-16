rule sha384_hashed_default_creds_telco_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telco_systems."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb0c628670f5f51cf994a81f97d7d492dd85e23ddf3b89f51cb2ab70d95d646e3ebd8eeb6bf56fb60377a5f832a04d6a"
    $a1="eb0c628670f5f51cf994a81f97d7d492dd85e23ddf3b89f51cb2ab70d95d646e3ebd8eeb6bf56fb60377a5f832a04d6a"
condition:
    ($a0 and $a1)
}