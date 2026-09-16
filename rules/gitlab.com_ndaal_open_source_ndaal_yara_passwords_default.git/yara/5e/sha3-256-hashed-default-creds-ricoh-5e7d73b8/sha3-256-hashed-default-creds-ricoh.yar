rule sha3_256_hashed_default_creds_ricoh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ricoh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="78377bddcc5fb7199a28965a65772069ce9de533aa0b7ac7c63fde2e2cc95966"
    $a4="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a5="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}