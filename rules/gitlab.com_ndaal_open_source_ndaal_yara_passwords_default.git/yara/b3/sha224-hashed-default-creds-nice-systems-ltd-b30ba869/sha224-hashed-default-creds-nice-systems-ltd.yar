rule sha224_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a8f86c56ca069a5fb9b3e055f56a6564fe63d0866d9e1cf7c4b9760"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="0a8f86c56ca069a5fb9b3e055f56a6564fe63d0866d9e1cf7c4b9760"
    $a3="6591013f07ce88246fba141ee0914f0595ed05685e84ff43a8dc133b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}