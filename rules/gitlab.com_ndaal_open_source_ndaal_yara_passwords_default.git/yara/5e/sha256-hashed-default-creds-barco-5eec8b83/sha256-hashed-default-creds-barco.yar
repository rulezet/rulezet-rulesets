rule sha256_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d21f85ea38166303ce58e06134b5cc4a5c900c409ab2a500ff7c9225109a09bb"
    $a1="9f088dbebd6c3c70a5ddbc2c943b11e4ca9acea5757b0b4f2b32479f0dbb747e"
condition:
    ($a0 and $a1)
}