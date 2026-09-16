rule sha384_hashed_default_creds_airaya_corp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for airaya_corp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f9e229947ad542524619c7c253c5e30f2735f2b62099d43dbd932abb78f32716d2f683afdc2ff3c817ba2246ae3a66cd"
    $a1="f9e229947ad542524619c7c253c5e30f2735f2b62099d43dbd932abb78f32716d2f683afdc2ff3c817ba2246ae3a66cd"
condition:
    ($a0 and $a1)
}