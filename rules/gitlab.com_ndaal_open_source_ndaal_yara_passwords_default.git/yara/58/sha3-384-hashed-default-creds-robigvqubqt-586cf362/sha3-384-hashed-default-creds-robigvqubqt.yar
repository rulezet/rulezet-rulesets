rule sha3_384_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="524741e7bd93bd7dc11cb53dbbe9b33270ab5872e5370fadef088d5a43d0094b0c3d9c789461e90300b0b9d71154b7d1"
    $a1="213c3dbc308ef42a48cf27bde3b9e5347ca16acfcffef1af54f214125c312402a88e8c7a65617657ed86edccabb2828b"
condition:
    ($a0 and $a1)
}