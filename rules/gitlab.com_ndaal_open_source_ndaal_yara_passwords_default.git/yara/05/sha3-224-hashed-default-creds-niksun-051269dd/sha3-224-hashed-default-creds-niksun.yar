rule sha3_224_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="540a18a8ae6396f3bba8c66b521c2614e81f1bd0559185cbc6b7601a"
    $a1="df36674a8da336c83804938538e2456b388779e2cac9534c4c1b11a6"
condition:
    ($a0 and $a1)
}