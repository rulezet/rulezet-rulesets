rule sha3_384_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ec95885e45b56e07b00a3635c5ce9b0196915779b64c25dd1dd743cb5c8e7f21cd05c97d0ca826d885815455b890558"
    $a1="d09a109d78344b0b94f5face9b082bec0cc1623e33cbec988ff01601fa34ba3d3bdd2886b773a11e55a88877b44c95a5"
condition:
    ($a0 and $a1)
}