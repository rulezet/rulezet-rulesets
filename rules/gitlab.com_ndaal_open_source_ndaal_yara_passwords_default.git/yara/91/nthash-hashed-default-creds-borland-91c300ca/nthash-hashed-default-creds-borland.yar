rule nthash_hashed_default_creds_borland
{
    meta:
        id = "4sdqG3RFL09dMUza6X2PVo"
        fingerprint = "2e0480135a267e188cee11f458730143b8f54123833e8d2a6f1c8b142cbc16eb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47f0f9abb19d8ccdb540fa9408fcd7fa"
    $a1="aaad087a8066ec7ecbd0f95514d443f4"
    $a2="47f0f9abb19d8ccdb540fa9408fcd7fa"
    $a3="9728a458444cfd9e0d68ee855fa8aa33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}