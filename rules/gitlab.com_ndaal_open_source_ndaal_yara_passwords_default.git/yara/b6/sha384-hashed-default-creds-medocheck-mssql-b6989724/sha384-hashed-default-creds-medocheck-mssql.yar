rule sha384_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83e38f641f936ac169870158b6d196f2323f16feb2dc6e1987f8baff4400779dc83f7211c6297b88046cd1acee448e51"
    $a1="6076f333edef23c401fd1e10ca7e7042e2cf3bdf0f7e0b2cd438ca749ae015c893a8e9c47152939813f68c6aa9fe0750"
condition:
    ($a0 and $a1)
}