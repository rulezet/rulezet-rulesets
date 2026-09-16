rule sha224_hashed_default_creds_360_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aaa4bcff925fb93b9014e8d9f80453e7f9eed710d986541b176677c0"
    $a1="aaa4bcff925fb93b9014e8d9f80453e7f9eed710d986541b176677c0"
condition:
    ($a0 and $a1)
}