rule sha3_256_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9e60db57b96a31d91a6e93b7f4416d257d0b22ab081e6b293e7d23301a9521fd"
    $a1="afec5811ca4b60e82f6b4f88b484edd8420f01539205074dd897fe9003c11c8f"
condition:
    ($a0 and $a1)
}