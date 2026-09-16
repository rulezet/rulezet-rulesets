rule sha512_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c946ba736c9d7cc4ba42ce723bfa3f53116b2b18065bf3a7f7feeb371e213916aef6072619f3882538c9b2c912c565aed42a11183ead6528ddb575e1f6e85ea5"
    $a1="c946ba736c9d7cc4ba42ce723bfa3f53116b2b18065bf3a7f7feeb371e213916aef6072619f3882538c9b2c912c565aed42a11183ead6528ddb575e1f6e85ea5"
condition:
    ($a0 and $a1)
}