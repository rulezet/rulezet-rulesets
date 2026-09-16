rule sha256_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="358842a6104f00fef15a0c322f6bc7d2a616dd4fbbd9508ac1e4c7282d9373a4"
    $a1="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a2="b769a6983b42d565e79bb4f3f534623453f301d39784e57804a649a67ea05327"
    $a3="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}