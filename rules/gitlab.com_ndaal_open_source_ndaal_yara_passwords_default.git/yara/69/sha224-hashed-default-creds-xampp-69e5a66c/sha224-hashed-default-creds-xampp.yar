rule sha224_hashed_default_creds_xampp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6e58d0f0858cc84231c22d5abd694d533870e72e69e182cf90da11e"
    $a1="d75b483573d8c841c5eae105e6938eae6d73de6fcbf408b7ac0cf986"
condition:
    ($a0 and $a1)
}