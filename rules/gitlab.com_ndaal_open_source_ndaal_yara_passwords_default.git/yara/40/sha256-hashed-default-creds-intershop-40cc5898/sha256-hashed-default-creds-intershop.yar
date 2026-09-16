rule sha256_hashed_default_creds_intershop
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intershop."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd394ab9110a0ce7e4af3d528808fb6cce00c786dc5096f0e632d1d5b27c5634"
    $a1="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
condition:
    ($a0 and $a1)
}