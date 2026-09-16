rule blake2b_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7d2e7147ab744f008ee2071e3e3f8ef17b505d9505bba3f0de7b762271de4ebd3ce553d1069ab1bd5f8ed80a53d98de2d08fbccfc4fb905e262523a5136e331"
    $a1="a63e3bfcafe40e9c85820bb2d686c7b0780c445170611930a2645ad5086eaf7aa2b918ccd4526019f05a235bad1862ce32c9a755d488d69e471de99d125b56df"
condition:
    ($a0 and $a1)
}