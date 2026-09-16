rule sha3_384_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8530f35f614ef2f40a0f294dd9aa2a7d493535978a595bf063479de204b09632e14b489c902fbb31ac2772da93900b2"
    $a1="9b815df57e54c070959b601385da424d2b7b1b9d55045e3e9af4bb2b11e563ddaf7d0070a343e8d5f7224d911ec638fd"
condition:
    ($a0 and $a1)
}