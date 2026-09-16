rule sha1_hashed_default_creds_corecess
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for corecess."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3320737101220f6507da223cfccc68278647b59"
    $a1="a3320737101220f6507da223cfccc68278647b59"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}