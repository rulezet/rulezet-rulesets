rule sha384_hashed_default_creds_alien_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bca8ac0bacf8ec571da74c19880f4867d1c004064320586527cdb010743885ad0eee3c14a6d3a52bee52daf1d522c28"
    $a1="1bca8ac0bacf8ec571da74c19880f4867d1c004064320586527cdb010743885ad0eee3c14a6d3a52bee52daf1d522c28"
    $a2="1bca8ac0bacf8ec571da74c19880f4867d1c004064320586527cdb010743885ad0eee3c14a6d3a52bee52daf1d522c28"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}