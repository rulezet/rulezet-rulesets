rule sha256_hashed_default_creds_fortinet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="9c5646b582f10531c791dd2372854409c96e8276f979c0aa4a505ec760e06100"
    $a2="89278f2c5f29dbac4db00a0bc78ab974c21166e5560d8173b4c28dd430fb2f5e"
    $a3="9c5646b582f10531c791dd2372854409c96e8276f979c0aa4a505ec760e06100"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}