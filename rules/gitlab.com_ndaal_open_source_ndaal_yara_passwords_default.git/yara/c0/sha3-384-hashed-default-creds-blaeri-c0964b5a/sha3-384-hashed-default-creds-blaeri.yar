rule sha3_384_hashed_default_creds_blaeri
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="195a1be4260035e37ff4042deacef04ab5e629efad8f5fa64de929ae8f793f930f74edb463f775773af98ff78538e3c2"
    $a1="eb6bc5d2c16512dba428f109452ab6c9d45977d38cdd0bf681b1b29361ac6b7793c8fe7ac9fea7b37017728a82071f58"
condition:
    ($a0 and $a1)
}