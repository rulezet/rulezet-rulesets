rule sha3_256_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="daeed6308874de11ec5ba896aff636aee60821b397f88164be3eae5cf6d276d8"
    $a3="daeed6308874de11ec5ba896aff636aee60821b397f88164be3eae5cf6d276d8"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="2772e4f1e650d0bb4058b1449b5ce3191dfefd0ba0aabc94418af2b330d5b062"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}