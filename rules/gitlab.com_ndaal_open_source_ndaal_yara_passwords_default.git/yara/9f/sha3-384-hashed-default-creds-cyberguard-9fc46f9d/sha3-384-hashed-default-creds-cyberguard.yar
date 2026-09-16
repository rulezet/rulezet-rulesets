rule sha3_384_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3852a045d1e81718f011eb6514c88348c07ce1acbd3e42c4dd7e9c1dfe1277b7db8ce12118ceca2174a4587bd097ebef"
    $a1="3852a045d1e81718f011eb6514c88348c07ce1acbd3e42c4dd7e9c1dfe1277b7db8ce12118ceca2174a4587bd097ebef"
condition:
    ($a0 and $a1)
}