rule sha3_384_hashed_default_creds_telco_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telco_systems."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed9a753f586338d24652bc9b686765d247bfee1a2cea89a0a4d42ef20ac186f1159ddd601f191f0ece7cbc5fd1ba2ca2"
    $a1="ed9a753f586338d24652bc9b686765d247bfee1a2cea89a0a4d42ef20ac186f1159ddd601f191f0ece7cbc5fd1ba2ca2"
condition:
    ($a0 and $a1)
}